/* Build time defaults. All of these can be overridden on the command line, see README.md. */

#ifndef SSH_CONFIG_H_
#define SSH_CONFIG_H_

#define SSH_DEFAULT_PORT     22
#define SSH_DEFAULT_USER     "admin"
#define SSH_DEFAULT_PASS     "admin"
#define SSH_SERVER_VERSION   "SSH-2.0-UefiSshShell_0.1"

/* Passed to the nested Shell as its load options. Empty string means none. */
#define SSH_DEFAULT_SHELL_OPTS "-nostartup"

/* Auth attempts per connection before the client is dropped. */
#define SSH_MAX_AUTH_TRIES   5

#endif
