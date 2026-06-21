/*
 * main.c - PQ Chat GTK3 GUI.
 *
 * A small front-end over the secure session engine in session.c. One peer
 * listens on a port; the other connects to it. After a post-quantum handshake
 * the link is symmetric and every message is protected by a Double Ratchet
 * (forward secrecy + post-compromise security). The network wait and the
 * per-message authenticated encryption run on a worker thread so the UI never
 * freezes; sending happens inline (messages are tiny) and is mutex-guarded
 * against the receive loop inside the engine.
 */
#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include "session.h"
#include "secure_buffer.h"

#ifndef PQCHAT_VERSION
#define PQCHAT_VERSION "1.0.1"
#endif
#define APP_ID       "org.pqchat.PQChat"
#define DEFAULT_PORT "5810"

/* Cyber-styled dark theme, shared lineage with the rest of the suite. */
static const char *APP_CSS =
    "window, .pqc-root {"
    "  background-color: #070b12;"
    "  color: #c8f7ff;"
    "}"
    "headerbar, .titlebar {"
    "  background: linear-gradient(90deg, #0a0f1a, #0e1726, #0a0f1a);"
    "  border-bottom: 1px solid #00e5ff;"
    "  box-shadow: 0 1px 8px rgba(0,229,255,0.35);"
    "  min-height: 40px;"
    "}"
    ".hb-title {"
    "  color: #00e5ff; font-family: monospace; font-weight: bold;"
    "  letter-spacing: 2px;"
    "}"
    "headerbar button {"
    "  padding: 2px 10px; margin: 4px 2px; min-height: 0; min-width: 0;"
    "  letter-spacing: 0;"
    "}"
    "headerbar button.titlebutton {"
    "  padding: 2px; margin: 2px; min-height: 22px; min-width: 22px;"
    "  background: transparent; border-color: transparent;"
    "}"
    "label { color: #9fd6e6; font-family: monospace; }"
    ".field-label { color: #5fb4c9; letter-spacing: 1px; }"
    ".brand {"
    "  color: #00e5ff; font-family: monospace; font-weight: bold;"
    "  font-size: 16px; letter-spacing: 5px;"
    "}"
    ".subtitle { color: #3d7d8f; font-size: 10px; letter-spacing: 3px; }"
    "entry {"
    "  background-color: #0c1421; color: #d8feff;"
    "  border: 1px solid #14384a;"
    "  border-radius: 4px; padding: 7px; font-family: monospace;"
    "  caret-color: #00e5ff;"
    "}"
    "entry:focus {"
    "  border-color: #00e5ff;"
    "  box-shadow: 0 0 6px rgba(0,229,255,0.6);"
    "}"
    "radiobutton, checkbutton { color: #9fd6e6; font-family: monospace; }"
    "radiobutton check, checkbutton check {"
    "  background-color: #0c1421; border: 1px solid #2a6b80;"
    "}"
    "radiobutton check:checked, checkbutton check:checked {"
    "  background-color: #00e5ff; border-color: #00e5ff;"
    "}"
    /* Every button uses black text. The label inside a button is colored via
     * the generic `label` rule above, which would otherwise win over the
     * button's own color through inheritance; `button label` is more specific,
     * so it makes the text reliably black on every button. Plain buttons get a
     * lighter fill so the black stays readable. */
    "button {"
    "  background: #5fc6dc; color: #000000;"
    "  border: 1px solid #00e5ff; border-radius: 4px;"
    "  padding: 7px 14px; font-family: monospace; letter-spacing: 1px;"
    "}"
    "button label { color: #000000; }"
    "button:hover {"
    "  border-color: #00e5ff;"
    "  box-shadow: 0 0 8px rgba(0,229,255,0.45);"
    "}"
    "button:active { background: #4aacc1; }"
    "button:disabled { background: #16313e; border-color: #16313e; }"
    "button:disabled label { color: #3a566a; }"
    ".action-button {"
    "  background: linear-gradient(90deg, #00b3c4, #00e5ff);"
    "  color: #000000; font-weight: bold; letter-spacing: 2px;"
    "  border: 1px solid #00e5ff;"
    "}"
    ".action-button:hover {"
    "  box-shadow: 0 0 14px rgba(0,229,255,0.8); color: #000000;"
    "}"
    ".danger-button {"
    "  background: linear-gradient(90deg, #ff3b6b, #ff6f8f);"
    "  color: #000000; font-weight: bold; letter-spacing: 2px;"
    "  border: 1px solid #ff426f;"
    "}"
    ".danger-button:hover {"
    "  box-shadow: 0 0 12px rgba(255,66,111,0.7); color: #000000;"
    "}"
    "textview, textview text {"
    "  background-color: #060a10; color: #c8f7ff;"
    "  font-family: monospace; font-size: 12px;"
    "}"
    "textview { padding: 10px; }"
    "scrolledwindow {"
    "  border: 1px solid #14384a; border-radius: 4px;"
    "}"
    "frame > border { border: 1px solid #14384a; border-radius: 4px; }"
    ".status-ok { color: #39ff14; }"
    ".status-err { color: #ff426f; }"
    ".status-run { color: #00e5ff; }";

/* UI states. */
typedef enum { ST_IDLE, ST_CONNECTING, ST_CONNECTED } ui_state;

typedef struct {
    GtkApplication *gapp;
    GtkWidget *window;
    GtkWidget *radio_listen;
    GtkWidget *radio_connect;
    GtkWidget *host_label;
    GtkWidget *host_entry;
    GtkWidget *port_entry;
    GtkWidget *pass_entry;
    GtkWidget *reveal_check;
    GtkWidget *connect_btn;
    GtkWidget *chat_view;
    GtkTextBuffer *chat_buf;
    GtkWidget *msg_entry;
    GtkWidget *send_btn;
    GtkWidget *status;

    ui_state          state;
    volatile int      cancel;        /* asks the worker to stop              */
    volatile int      window_gone;   /* window destroyed                     */
    pqc_chan * volatile chan;        /* live channel (set/cleared on GUI thr)*/
} App;

/* Worker context: a snapshot of the connection parameters. */
typedef struct {
    App        *app;
    pqc_config  cfg;
} WorkerCtx;

/* Idle events posted from the worker thread to the GUI thread. */
typedef enum { EV_CONNECTED, EV_READY, EV_MSG, EV_ENDED } ev_type;
typedef struct {
    App       *app;
    ev_type    type;
    pqc_chan  *chan;     /* EV_CONNECTED */
    char      *text;     /* EV_MSG (heap) */
    char      *msg;      /* EV_ENDED reason (heap, may be NULL) */
    int        ok;       /* EV_ENDED */
} Ev;

/* ----- transcript helpers ---------------------------------------------- */

static void append_line(App *app, const char *prefix, const char *tag,
                        const char *body) {
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(app->chat_buf, &end);
    if (gtk_text_buffer_get_char_count(app->chat_buf) > 0)
        gtk_text_buffer_insert(app->chat_buf, &end, "\n", -1);
    if (prefix && *prefix) {
        gtk_text_buffer_insert_with_tags_by_name(app->chat_buf, &end, prefix, -1,
                                                 tag, "bold", NULL);
        gtk_text_buffer_get_end_iter(app->chat_buf, &end);
    }
    gtk_text_buffer_insert_with_tags_by_name(app->chat_buf, &end, body, -1, tag, NULL);

    /* Autoscroll to the newest line. */
    GtkTextMark *mark = gtk_text_buffer_get_insert(app->chat_buf);
    gtk_text_buffer_get_end_iter(app->chat_buf, &end);
    gtk_text_buffer_move_mark(app->chat_buf, mark, &end);
    gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(app->chat_view), mark, 0.0, TRUE, 0.0, 1.0);
}

static void sys_line(App *app, const char *text) {
    append_line(app, "", "sys", text);
}

static void set_status(App *app, const char *cls, const char *text) {
    GtkStyleContext *sc = gtk_widget_get_style_context(app->status);
    gtk_style_context_remove_class(sc, "status-ok");
    gtk_style_context_remove_class(sc, "status-err");
    gtk_style_context_remove_class(sc, "status-run");
    if (cls) gtk_style_context_add_class(sc, cls);
    gtk_label_set_text(GTK_LABEL(app->status), text);
}

/* ----- UI state -------------------------------------------------------- */

static void apply_state(App *app) {
    gboolean idle = (app->state == ST_IDLE);
    gtk_widget_set_sensitive(app->radio_listen, idle);
    gtk_widget_set_sensitive(app->radio_connect, idle);
    gtk_widget_set_sensitive(app->host_entry, idle);
    gtk_widget_set_sensitive(app->port_entry, idle);
    gtk_widget_set_sensitive(app->pass_entry, idle);

    gboolean can_chat = (app->state == ST_CONNECTED);
    gtk_widget_set_sensitive(app->msg_entry, can_chat);
    gtk_widget_set_sensitive(app->send_btn, can_chat);

    GtkStyleContext *bc = gtk_widget_get_style_context(app->connect_btn);
    gtk_style_context_remove_class(bc, "action-button");
    gtk_style_context_remove_class(bc, "danger-button");
    if (app->state == ST_IDLE) {
        gboolean listen = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->radio_listen));
        gtk_button_set_label(GTK_BUTTON(app->connect_btn), listen ? "LISTEN" : "CONNECT");
        gtk_style_context_add_class(bc, "action-button");
    } else if (app->state == ST_CONNECTING) {
        gtk_button_set_label(GTK_BUTTON(app->connect_btn), "CANCEL");
        gtk_style_context_add_class(bc, "danger-button");
    } else {
        gtk_button_set_label(GTK_BUTTON(app->connect_btn), "DISCONNECT");
        gtk_style_context_add_class(bc, "danger-button");
    }
}

static void free_app(App *app) { g_free(app); }

/* ----- idle event dispatch (GUI thread) -------------------------------- */

static gboolean ev_dispatch(gpointer data) {
    Ev *ev = data;
    App *app = ev->app;

    switch (ev->type) {
    case EV_CONNECTED:
        app->chan = ev->chan;
        if (!app->window_gone) {
            app->state = ST_CONNECTED;
            apply_state(app);
            sys_line(app, "\xF0\x9F\x94\x92 Secure channel established "
                          "(Kyber-1024 + X448, Double Ratchet).");
            gboolean listen = gtk_toggle_button_get_active(
                GTK_TOGGLE_BUTTON(app->radio_listen));
            if (listen) {
                set_status(app, "status-run", "\xE2\x96\xB6 Secured. Waiting for the peer to speak\xE2\x80\xA6");
                /* Listener cannot send until it has received the priming
                 * message, so keep the composer disabled until EV_READY. */
                gtk_widget_set_sensitive(app->msg_entry, FALSE);
                gtk_widget_set_sensitive(app->send_btn, FALSE);
            } else {
                set_status(app, "status-ok", "\xE2\x9C\x94 Connected. You can chat now.");
                gtk_widget_grab_focus(app->msg_entry);
            }
        }
        break;

    case EV_READY:
        if (!app->window_gone && app->state == ST_CONNECTED) {
            gtk_widget_set_sensitive(app->msg_entry, TRUE);
            gtk_widget_set_sensitive(app->send_btn, TRUE);
            set_status(app, "status-ok", "\xE2\x9C\x94 Peer connected. You can chat now.");
            gtk_widget_grab_focus(app->msg_entry);
        }
        break;

    case EV_MSG:
        if (!app->window_gone)
            append_line(app, "peer \xE2\x96\xB8 ", "peer", ev->text ? ev->text : "");
        g_free(ev->text);
        break;

    case EV_ENDED:
        /* The worker has fully stopped using the channel; free it here. */
        if (app->chan) { pqc_close(app->chan); app->chan = NULL; }
        if (!app->window_gone) {
            app->state = ST_IDLE;
            app->cancel = 0;
            apply_state(app);
            if (ev->ok)
                set_status(app, "status-err", ev->msg ? ev->msg : "Disconnected.");
            else
                set_status(app, "status-err", ev->msg ? ev->msg : "Connection failed.");
            gchar *line = g_strdup_printf("\xE2\x80\x94 %s \xE2\x80\x94",
                                          ev->msg ? ev->msg : "Disconnected.");
            sys_line(app, line);
            g_free(line);
        }
        g_free(ev->msg);
        g_application_release(G_APPLICATION(app->gapp));
        if (app->window_gone) free_app(app);
        break;
    }
    g_free(ev);
    return G_SOURCE_REMOVE;
}

static void post_ev(App *app, ev_type type, pqc_chan *chan,
                    char *text, char *msg, int ok) {
    Ev *ev = g_new0(Ev, 1);
    ev->app = app; ev->type = type; ev->chan = chan;
    ev->text = text; ev->msg = msg; ev->ok = ok;
    g_idle_add(ev_dispatch, ev);
}

/* ----- worker thread --------------------------------------------------- */

static gpointer worker_thread(gpointer data) {
    WorkerCtx *ctx = data;
    App *app = ctx->app;
    char err[256] = {0};
    pqc_chan *c = NULL;

    if (pqc_connect(&ctx->cfg, &c, &app->cancel, err, sizeof(err)) != 0) {
        post_ev(app, EV_ENDED, NULL, NULL,
                g_strdup(err[0] ? err : "Connection failed."), 0);
        sodium_munlock(ctx->cfg.passphrase, sizeof(ctx->cfg.passphrase));
        g_free(ctx);
        return NULL;
    }

    post_ev(app, EV_CONNECTED, c, NULL, NULL, 0);

    char endmsg[256] = "Disconnected.";
    for (;;) {
        char text[PQC_MSG_MAX + 1];
        int is_chat = 0;
        char rerr[256] = {0};
        int r = pqc_recv(c, text, sizeof(text), &is_chat, &app->cancel,
                         rerr, sizeof(rerr));
        if (r == 1) { g_strlcpy(endmsg, "Disconnected.", sizeof(endmsg)); break; }
        if (r != 0) {
            g_strlcpy(endmsg, rerr[0] ? rerr : "Peer disconnected.", sizeof(endmsg));
            break;
        }
        if (is_chat) post_ev(app, EV_MSG, NULL, g_strdup(text), NULL, 0);
        else         post_ev(app, EV_READY, NULL, NULL, NULL, 0);
        sodium_memzero(text, sizeof(text));
    }

    /* Channel is freed by the GUI thread in EV_ENDED (it may still be sending
     * up to this point); we no longer touch it after posting. */
    post_ev(app, EV_ENDED, NULL, NULL, g_strdup(endmsg), 1);
    sodium_munlock(ctx->cfg.passphrase, sizeof(ctx->cfg.passphrase));
    g_free(ctx);
    return NULL;
}

/* ----- UI callbacks ---------------------------------------------------- */

static void warn(App *app, const char *msg) {
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(app->window),
        GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK, "%s", msg);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

static void on_reveal_toggled(GtkToggleButton *btn, gpointer user) {
    App *app = user;
    gtk_entry_set_visibility(GTK_ENTRY(app->pass_entry), gtk_toggle_button_get_active(btn));
}

static void on_mode_toggled(GtkToggleButton *btn, gpointer user) {
    (void)btn;
    App *app = user;
    gboolean listen = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->radio_listen));
    gtk_label_set_text(GTK_LABEL(app->host_label), listen ? "Listen on:" : "Peer host:");
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->host_entry),
                       listen ? "blank = all interfaces" : "e.g. 192.168.1.42");
    if (app->state == ST_IDLE)
        gtk_button_set_label(GTK_BUTTON(app->connect_btn), listen ? "LISTEN" : "CONNECT");
}

static void start_session(App *app) {
    gboolean listen = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->radio_listen));
    const char *host = gtk_entry_get_text(GTK_ENTRY(app->host_entry));
    const char *ports = gtk_entry_get_text(GTK_ENTRY(app->port_entry));
    const char *pass = gtk_entry_get_text(GTK_ENTRY(app->pass_entry));

    if (!listen && (!host || !*host)) { warn(app, "Enter the peer's host or IP address."); return; }
    int port = (ports && *ports) ? atoi(ports) : 0;
    if (port < 1 || port > 65535) { warn(app, "Enter a port between 1 and 65535."); return; }
    if (strlen(pass) >= PQC_PASS_MAX) { warn(app, "Passphrase is too long."); return; }
    if (host && strlen(host) >= sizeof(((pqc_config *)0)->host)) { warn(app, "Host is too long."); return; }

    WorkerCtx *ctx = g_new0(WorkerCtx, 1);
    sodium_mlock(ctx->cfg.passphrase, sizeof(ctx->cfg.passphrase));
    ctx->app = app;
    ctx->cfg.listen = listen ? 1 : 0;
    ctx->cfg.port = (uint16_t)port;
    g_strlcpy(ctx->cfg.host, host ? host : "", sizeof(ctx->cfg.host));
    g_strlcpy(ctx->cfg.passphrase, pass ? pass : "", sizeof(ctx->cfg.passphrase));

    app->cancel = 0;
    app->state = ST_CONNECTING;
    apply_state(app);
    set_status(app, "status-run",
               listen ? "\xE2\x96\xB6 Listening for an incoming connection\xE2\x80\xA6"
                      : "\xE2\x96\xB6 Connecting and negotiating keys\xE2\x80\xA6");

    g_application_hold(G_APPLICATION(app->gapp));
    GError *gerr = NULL;
    GThread *t = g_thread_try_new("pqc-worker", worker_thread, ctx, &gerr);
    if (!t) {
        g_application_release(G_APPLICATION(app->gapp));
        app->state = ST_IDLE;
        apply_state(app);
        set_status(app, "status-err", "\xE2\x9C\x96 Could not start worker thread.");
        sodium_munlock(ctx->cfg.passphrase, sizeof(ctx->cfg.passphrase));
        g_free(ctx);
        if (gerr) g_error_free(gerr);
        return;
    }
    g_thread_unref(t);
}

static void on_connect(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    if (app->state == ST_IDLE) {
        start_session(app);
    } else {
        /* Connecting or connected: this button disconnects. */
        app->cancel = 1;
        set_status(app, "status-run", "\xE2\x96\xB6 Disconnecting\xE2\x80\xA6");
    }
}

static void do_send(App *app) {
    if (app->state != ST_CONNECTED || !app->chan) return;
    const char *text = gtk_entry_get_text(GTK_ENTRY(app->msg_entry));
    if (!text || !*text) return;
    char err[256] = {0};
    if (pqc_send(app->chan, text, err, sizeof(err)) == 0) {
        append_line(app, "you \xE2\x96\xB8 ", "you", text);
        gtk_entry_set_text(GTK_ENTRY(app->msg_entry), "");
    } else {
        set_status(app, "status-err", err[0] ? err : "Send failed.");
        app->cancel = 1;   /* tear the session down on a send error */
    }
}

static void on_send_clicked(GtkButton *b, gpointer user) { (void)b; do_send(user); }
static void on_msg_activate(GtkEntry *e, gpointer user)  { (void)e; do_send(user); }

static void on_about(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    const gchar *authors[] = { "Jean-Francois Lachance-Caumartin", NULL };
    const gchar *features =
        "PQ Chat is a serverless, end-to-end encrypted messenger. One peer\n"
        "listens, the other connects — no server, no cloud, no accounts.\n\n"
        "Features:\n"
        "• Post-quantum handshake (Kyber-1024 + X448 hybrid KEM): the session\n"
        "  key stays secure as long as either primitive holds\n"
        "• Double Ratchet for every message — forward secrecy and\n"
        "  post-compromise security (Signal's algorithm over X448)\n"
        "• XChaCha20-Poly1305 authenticated encryption, fresh key per message\n"
        "• Optional shared passphrase via a real CPace PAKE (Ristretto255):\n"
        "  authenticates the channel with no offline dictionary attack\n"
        "• Hardened memory: passphrases and keys live in locked, non-dumpable\n"
        "  memory and never hit swap";

    GtkWidget *d = gtk_about_dialog_new();
    GtkAboutDialog *ad = GTK_ABOUT_DIALOG(d);
    gtk_about_dialog_set_program_name(ad, "PQ Chat");
    gtk_about_dialog_set_version(ad, PQCHAT_VERSION);
    gtk_about_dialog_set_comments(ad, features);
    gtk_about_dialog_set_authors(ad, authors);
    gtk_about_dialog_set_copyright(ad, "© 2026 Jean-Francois Lachance-Caumartin");
    gtk_about_dialog_set_license_type(ad, GTK_LICENSE_MIT_X11);
    gtk_about_dialog_set_logo_icon_name(ad, "pqchat");
    gtk_window_set_transient_for(GTK_WINDOW(d), GTK_WINDOW(app->window));
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

/* ----- layout helpers -------------------------------------------------- */

static GtkWidget *field(const char *text, GtkWidget *widget, gboolean expand) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *lbl = gtk_label_new(text);
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl), "field-label");
    gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), widget, expand, expand, 0);
    return box;
}

static void on_window_destroy(GtkWidget *w, gpointer user) {
    (void)w;
    App *app = user;
    app->window_gone = 1;
    if (app->state != ST_IDLE) {
        /* A worker is running; it owns the app's lifetime and will free it
         * (and the channel) when it posts EV_ENDED. */
        app->cancel = 1;
    } else {
        free_app(app);
    }
}

static void load_css(void) {
    GtkCssProvider *p = gtk_css_provider_new();
    gtk_css_provider_load_from_data(p, APP_CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(), GTK_STYLE_PROVIDER(p),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}

static void activate(GtkApplication *gapp, gpointer user) {
    (void)user;
    App *app = g_new0(App, 1);
    app->gapp = gapp;
    app->state = ST_IDLE;

    load_css();

    app->window = gtk_application_window_new(gapp);
    gtk_window_set_title(GTK_WINDOW(app->window), "PQ Chat");
    /* Wide and short, comfortably within a 1366x768 display. */
    gtk_window_set_default_size(GTK_WINDOW(app->window), 1100, 560);
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "pqchat");
    gtk_window_set_position(GTK_WINDOW(app->window), GTK_WIN_POS_CENTER);

    GtkWidget *hb = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hb), TRUE);
    GtkWidget *title_lbl = gtk_label_new("PQ CHAT  \xC2\xB7  v" PQCHAT_VERSION);
    gtk_style_context_add_class(gtk_widget_get_style_context(title_lbl), "hb-title");
    gtk_header_bar_set_custom_title(GTK_HEADER_BAR(hb), title_lbl);
    GtkWidget *hb_about = gtk_button_new_with_label("About");
    g_signal_connect(hb_about, "clicked", G_CALLBACK(on_about), app);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(hb), hb_about);
    gtk_window_set_titlebar(GTK_WINDOW(app->window), hb);

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_style_context_add_class(gtk_widget_get_style_context(root), "pqc-root");
    gtk_container_set_border_width(GTK_CONTAINER(root), 14);
    gtk_container_add(GTK_CONTAINER(app->window), root);

    /* --- Connection bar (horizontal, across the top) --- */
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);

    GtkWidget *brand = gtk_label_new("\xE2\x9C\xA6 PQ CHAT");
    gtk_style_context_add_class(gtk_widget_get_style_context(brand), "brand");
    gtk_box_pack_start(GTK_BOX(bar), brand, FALSE, FALSE, 4);

    GtkWidget *mode_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    app->radio_connect = gtk_radio_button_new_with_label(NULL, "Connect");
    app->radio_listen = gtk_radio_button_new_with_label_from_widget(
        GTK_RADIO_BUTTON(app->radio_connect), "Listen");
    gtk_box_pack_start(GTK_BOX(mode_box), app->radio_connect, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(mode_box), app->radio_listen, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), field("Mode:", mode_box, FALSE), FALSE, FALSE, 0);

    app->host_label = gtk_label_new("Peer host:");
    app->host_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->host_entry), "e.g. 192.168.1.42");
    gtk_entry_set_width_chars(GTK_ENTRY(app->host_entry), 16);
    {
        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
        gtk_box_pack_start(GTK_BOX(box), app->host_label, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(box), app->host_entry, TRUE, TRUE, 0);
        gtk_box_pack_start(GTK_BOX(bar), box, TRUE, TRUE, 0);
    }

    app->port_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(app->port_entry), DEFAULT_PORT);
    gtk_entry_set_width_chars(GTK_ENTRY(app->port_entry), 6);
    gtk_box_pack_start(GTK_BOX(bar), field("Port:", app->port_entry, FALSE), FALSE, FALSE, 0);

    GtkEntryBuffer *pass_buf = secure_entry_buffer_new();
    app->pass_entry = gtk_entry_new_with_buffer(pass_buf);
    g_object_unref(pass_buf);
    gtk_entry_set_visibility(GTK_ENTRY(app->pass_entry), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(app->pass_entry), GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->pass_entry), "shared secret (recommended)");
    gtk_entry_set_width_chars(GTK_ENTRY(app->pass_entry), 18);
    app->reveal_check = gtk_check_button_new_with_label("Reveal");
    g_signal_connect(app->reveal_check, "toggled", G_CALLBACK(on_reveal_toggled), app);
    {
        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
        GtkWidget *lbl = gtk_label_new("Passphrase:");
        gtk_style_context_add_class(gtk_widget_get_style_context(lbl), "field-label");
        gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(box), app->pass_entry, TRUE, TRUE, 0);
        gtk_box_pack_start(GTK_BOX(box), app->reveal_check, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(bar), box, TRUE, TRUE, 0);
    }

    app->connect_btn = gtk_button_new_with_label("CONNECT");
    gtk_style_context_add_class(gtk_widget_get_style_context(app->connect_btn), "action-button");
    g_signal_connect(app->connect_btn, "clicked", G_CALLBACK(on_connect), app);
    gtk_box_pack_start(GTK_BOX(bar), app->connect_btn, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(root), bar, FALSE, FALSE, 0);

    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(root), sep, FALSE, FALSE, 0);

    /* --- Transcript (fills the wide central area) --- */
    GtkWidget *scroller = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    app->chat_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app->chat_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(app->chat_view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(app->chat_view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(app->chat_view), 8);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(app->chat_view), 8);
    app->chat_buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->chat_view));
    gtk_text_buffer_create_tag(app->chat_buf, "you",  "foreground", "#39ff14", NULL);
    gtk_text_buffer_create_tag(app->chat_buf, "peer", "foreground", "#00e5ff", NULL);
    gtk_text_buffer_create_tag(app->chat_buf, "sys",  "foreground", "#5f8a99",
                               "style", PANGO_STYLE_ITALIC, NULL);
    gtk_text_buffer_create_tag(app->chat_buf, "bold", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_container_add(GTK_CONTAINER(scroller), app->chat_view);
    gtk_box_pack_start(GTK_BOX(root), scroller, TRUE, TRUE, 0);

    sys_line(app, "Ready. Pick Listen or Connect, optionally share a passphrase, "
                  "then start the secure channel.");

    /* --- Composer (bottom) --- */
    GtkWidget *compose = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    app->msg_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app->msg_entry), "Type a message and press Enter…");
    gtk_widget_set_sensitive(app->msg_entry, FALSE);
    g_signal_connect(app->msg_entry, "activate", G_CALLBACK(on_msg_activate), app);
    app->send_btn = gtk_button_new_with_label("SEND");
    gtk_style_context_add_class(gtk_widget_get_style_context(app->send_btn), "action-button");
    gtk_widget_set_sensitive(app->send_btn, FALSE);
    g_signal_connect(app->send_btn, "clicked", G_CALLBACK(on_send_clicked), app);
    gtk_box_pack_start(GTK_BOX(compose), app->msg_entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(compose), app->send_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), compose, FALSE, FALSE, 0);

    /* --- Status line --- */
    app->status = gtk_label_new("Disconnected.");
    gtk_label_set_xalign(GTK_LABEL(app->status), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(app->status), TRUE);
    gtk_box_pack_start(GTK_BOX(root), app->status, FALSE, FALSE, 0);

    g_signal_connect(app->radio_listen, "toggled", G_CALLBACK(on_mode_toggled), app);
    g_signal_connect(app->radio_connect, "toggled", G_CALLBACK(on_mode_toggled), app);
    g_signal_connect(app->window, "destroy", G_CALLBACK(on_window_destroy), app);

    gtk_widget_show_all(app->window);
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) {
        g_printerr("Failed to initialise libsodium.\n");
        return 1;
    }
    /* Keep secrets off disk: core dumps can contain keys and plaintext, so
     * disable them; on Linux also clear the dumpable flag (blocks ptrace and
     * /proc-based core capture). Per-buffer sodium_mlock in the engine covers
     * swap and marks those pages non-dumpable. */
    struct rlimit rl = { 0, 0 };
    setrlimit(RLIMIT_CORE, &rl);
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
    GtkApplication *gapp = gtk_application_new(APP_ID, G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(gapp, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(gapp), argc, argv);
    g_object_unref(gapp);
    return status;
}
