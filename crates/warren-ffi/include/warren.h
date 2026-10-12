/*
 * The C interface of warren's client core, for the native platform shells
 * (the macOS menu-bar app and its packet tunnel provider).
 *
 * Strings are NUL-terminated UTF-8. Every string a function returns is
 * owned by the caller and must be released with warren_string_free; NULL
 * is returned only where documented. JSON results carry either the result
 * or {"error": "...", "reason": "..."}, where the error is a sentence
 * written for people.
 *
 * Callbacks may be called from any thread, concurrently, until the
 * function that registered them has returned (warren_login) or until
 * warren_tunnel_stop has returned; ctx is passed back unchanged.
 */
#ifndef WARREN_H
#define WARREN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The client core's version, a static string (do not free). */
const char *warren_version(void);

/* Releases a string returned by this library. NULL is ignored. */
void warren_string_free(char *s);

/* The saved sign-in, device and apps in the state directory `home`, as
 * JSON (the shape of `warren status --json`, without "up"). */
char *warren_status_json(const char *home);

/* Asks the shell to open `url` in the user's browser. */
typedef void (*warren_open_url_fn)(void *ctx, const char *url);

/* Signs in to `org_url` and enrolls the device, keeping state in `home`.
 * `fingerprint` pins the deployment root (NULL: the system's trust store).
 * Blocks until the browser comes back or `timeout_secs` pass. Returns JSON
 * describing the user, the device and whether it awaits approval. */
char *warren_login(const char *home, const char *org_url, const char *fingerprint,
                   uint32_t timeout_secs, warren_open_url_fn open_url, void *ctx);

/* A running tunnel engine. */
typedef struct WarrenTunnel WarrenTunnel;

/* Hands an IP packet from the tunnel to the system. */
typedef void (*warren_deliver_fn)(void *ctx, const uint8_t *packet, size_t len);

/* Applies network settings, given as JSON: {"addresses": [...], "mtu": n,
 * "routes": ["10.0.0.0/8", ...], "skipped": [...]}. Returns whether the
 * system took them. */
typedef bool (*warren_settings_fn)(void *ctx, const char *settings_json);

/* Reports an event, as JSON with an "event" member, for the user. */
typedef void (*warren_event_fn)(void *ctx, const char *event_json);

/* Starts the engine for the account saved in `home`. On failure returns
 * NULL and, if `error` is not NULL, sets *error to a sentence explaining
 * why (free it with warren_string_free). */
WarrenTunnel *warren_tunnel_start(const char *home, void *ctx, warren_deliver_fn deliver,
                                  warren_settings_fn settings, warren_event_fn event,
                                  char **error);

/* Gives the engine a packet the system routed into the tunnel. */
void warren_tunnel_send(WarrenTunnel *tunnel, const uint8_t *packet, size_t len);

/* The engine's state as JSON (the shape of `warren status --json`). */
char *warren_tunnel_status_json(WarrenTunnel *tunnel);

/* Closes every tunnel, stops the engine and frees it. */
void warren_tunnel_stop(WarrenTunnel *tunnel);

#ifdef __cplusplus
}
#endif

#endif /* WARREN_H */
