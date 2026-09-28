# Why Trove has private SSH-agent sockets

The [CLI reference](cli-reference.md#trove-ssh-agent-empty) documents the commands, safe shell
usage, key limits, and socket lifecycle. This note records the incident and design tradeoffs behind
using a private, explicitly populated agent. For the measured OpenSSH protocol ordering, see
[the `session-bind@openssh.com` note](ssh-agent-session-bind.md).

## The incident

On a real bastion, `sshd` allowed six authentication attempts. Trove's agent held nine keys; the
wanted key was eighth in the list, so SSH disconnected before offering it. After the vault was
unlocked again, the same key appeared fifth. Agent order changed, making the failure intermittent
without any change to the deployment.

This is why the goal is to choose the keys before connecting, rather than trying keys until one
works. The CLI reference describes how SSH counts offers and how that interacts with `fail2ban`.

## Why the mapping is not inferred

A server's host key cannot identify the client's authorized key. The host key identifies the server;
a client public key contains only its key type and key material. The mapping from server to
authorized client key exists in `authorized_keys` on the server, which cannot be read without
connecting.

Pinning `IdentityFile` in SSH configuration can select a key, but it selects by path. A key held
only in a Trove vault would first have to be materialized as a file.

## Why a private, explicitly populated socket

A separate socket lets a caller select exactly the vault entries it intends to use without
changing the daemon's shared agent. Independent jobs can populate their own sockets without racing
over a shared list of keys. One socket can hold several selected keys for a multi-hop deployment.
An immutable socket per key would need separate agents for the jump host and destination; `ssh -J`
does not pass per-hop options to its nested SSH client, so that setup would require a `ProxyCommand`.

Host-key-based filtering is another option: `session-bind@openssh.com` identifies the server
before identities are listed, but it cannot tell Trove which of the user's keys that server accepts.
It still depends on a host-to-entry mapping. The [protocol measurement](ssh-agent-session-bind.md)
and [CLI reference](cli-reference.md#telling-the-agent-which-server-a-key-is-for) explain the
filter's behavior and its fallback. Explicitly adding entries makes the caller choose what to offer;
the isolated socket keeps concurrent jobs from mutating one another's key lists.

## Caller integration

The design was motivated by `pulumi-homelab`. Its subprocesses inherit `SSH_AUTH_SOCK`, so a single
scoped socket containing all keys needed by a deployment requires no Pulumi code change. The
existing `Host.identityFile` remains available as a fallback for keys outside Trove.

`SSH_AUTH_SOCK` is process-wide. If a future Pulumi run needs different, disjoint agents for
concurrent hosts, the caller would need per-host `IdentityAgent` configuration, including separate
handling for jump hosts. That is not needed when one scoped socket contains the deployment's
selected keys.
