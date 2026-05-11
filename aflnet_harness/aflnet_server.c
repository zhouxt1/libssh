/*
 * Single-connection TCP harness for libssh, for AFLNet fuzzing.
 *
 * Binds a TCP port, accepts ONE connection, runs the SSH server protocol
 * via libssh, then exits. Same "handle one then exit" model OpenSSH gets
 * from `sshd -d`, DropBear from DEBUG_NOFORK, and TinySSH from its in-
 * binary listener.
 *
 * Selects "none" cipher and MAC on both directions to remove encryption-
 * induced nondeterminism from AFL's coverage map. KEX is still random.
 */

#define LIBSSH_STATIC 1

#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct session_data {
    ssh_channel channel;
    int auth_attempts;
    bool authenticated;
};

static int auth_password(ssh_session s, const char *user, const char *pass,
                         void *userdata)
{
    struct session_data *sd = userdata;
    (void)s; (void)user; (void)pass;
    sd->authenticated = true;
    return SSH_AUTH_SUCCESS;
}

static int auth_none(ssh_session s, const char *user, void *userdata)
{
    struct session_data *sd = userdata;
    (void)s; (void)user;
    if (sd->auth_attempts > 0) {
        sd->authenticated = true;
    }
    sd->auth_attempts++;
    return sd->authenticated ? SSH_AUTH_SUCCESS : SSH_AUTH_PARTIAL;
}

static ssh_channel channel_open(ssh_session s, void *userdata)
{
    struct session_data *sd = userdata;
    sd->channel = ssh_channel_new(s);
    return sd->channel;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <port> <hostkey> [hostkey ...]\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);
    bool no = false;
    int rc;

    ssh_init();

    ssh_bind sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "ssh_bind_new failed\n");
        return 1;
    }

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "127.0.0.1");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_PROCESS_CONFIG, &no);

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_CIPHERS_C_S, "none");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_CIPHERS_S_C, "none");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HMAC_C_S,    "none");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HMAC_S_C,    "none");

    for (int i = 2; i < argc; i++) {
        rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, argv[i]);
        if (rc != SSH_OK) {
            fprintf(stderr, "hostkey %s: %s\n", argv[i],
                    ssh_get_error(sshbind));
            return 1;
        }
    }

    if (ssh_bind_listen(sshbind) < 0) {
        fprintf(stderr, "listen: %s\n", ssh_get_error(sshbind));
        return 1;
    }

    ssh_session session = ssh_new();
    if (session == NULL) {
        return 1;
    }

    struct session_data sd = {0};
    struct ssh_server_callbacks_struct cb = {
        .userdata = &sd,
        .auth_password_function = auth_password,
        .auth_none_function = auth_none,
        .channel_open_request_session_function = channel_open,
    };

    ssh_set_auth_methods(session,
                         SSH_AUTH_METHOD_NONE | SSH_AUTH_METHOD_PASSWORD);
    ssh_callbacks_init(&cb);
    ssh_set_server_callbacks(session, &cb);

    if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
        fprintf(stderr, "accept: %s\n", ssh_get_error(sshbind));
        goto cleanup;
    }

    ssh_event ev = ssh_event_new();
    if (ev == NULL) {
        goto cleanup;
    }

    if (ssh_handle_key_exchange(session) == SSH_OK) {
        ssh_event_add_session(ev, session);
        for (int n = 0; n < 100; n++) {
            if (sd.authenticated && sd.channel != NULL) break;
            if (sd.auth_attempts >= 3) break;
            if (ssh_event_dopoll(ev, 100) == SSH_ERROR) break;
        }
    } else {
        fprintf(stderr, "kex: %s\n", ssh_get_error(session));
    }

    ssh_event_free(ev);

cleanup:
    ssh_disconnect(session);
    ssh_free(session);
    ssh_bind_free(sshbind);
    ssh_finalize();
    return 0;
}
