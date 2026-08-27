# Prometheus two-host cold-restore answers

Date: 27 August 2026.

This page is for Jason Gale. This package is laboratory code under PolicyLab-2. This package is not Sanctum. This package is not a Cyera product.

This document uses ASD-STE100 Simplified Technical English. Technical names appear in full words.

This page is the operator recipe for a two-host cold restore. Jason can run this walk on hostname 5090. The walk uses throwaway directories only. Standing data-a is not the restore dest. This dest is not data-a. Do not write data-a. Do not use data-a. Do not start SPIRE. Do not use the member-two VPC path. A member-two path in this walk must live under /tmp.

The visible walk lives in `see-walk/cold-restore-two-host`. This folder holds public recipe text only. It does not hold `issuer.secret`, `biscuit.secret`, holder secrets, or member-two secrets.

GET / and GET /laboratory already have the backup, restore, and diagnose forms. This walk points at those pages. Init stays on the command line. Host start is a listen command.

## What this walk proves

1. Host A on 127.0.0.1 can write a backup to an outside /tmp path.
2. Host B on another 127.0.0.1 port can start with empty --data, restore that backup, and diagnose. Diagnose reports operation_normal.
3. Host B can mint Assertion Act as present-svid. Host B can mint present-wimse.
4. Restore on Host A refuses. That dest already has an issuer.
5. At issuance threshold_n 2, dest birth and present without the outside member path refuse.

Restore is restore. Restore is disaster recovery of the same issuer. Restore is not a separate product. A second live issuer is refused.

## Throwaway paths

Do not use data-a. Do not write data-a. Standing data-a is not the restore dest.

- Host A data: `/tmp/prometheus-cold-restore-two-host-a`
- Host B data: `/tmp/prometheus-cold-restore-two-host-b`
- Backup: `/tmp/prometheus-cold-restore-two-host-backup`
- Member two for the n=2 close: `/tmp/prometheus-cold-restore-two-host-member-two/member-two.secret`

Host A listens on `127.0.0.1:18850`. Host B listens on `127.0.0.1:18851`. Both hosts bind 127.0.0.1 only. This is not a public listener.

## How Jason opens the two laboratory pages

1. Start Host A. Open `http://127.0.0.1:18850/laboratory`. GET / on the same host is `http://127.0.0.1:18850/`.
2. Start Host B. Open `http://127.0.0.1:18851/laboratory`. GET / on the same host is `http://127.0.0.1:18851/`.

Both pages post POST /backup, POST /restore, and POST /diagnose.

## Operator steps

### 0. Tree and binary

```
source "$HOME/.cargo/env"
cd /home/jason/Projects/Prometheus
```

Do not clone. Use this tree. Use `./target/release/prometheus` after `cargo build --release`, or use `cargo run --`.

### 1. Issuing host A

Host A uses empty-then-inited throwaway --data.

```
rm -rf /tmp/prometheus-cold-restore-two-host-a
mkdir -p /tmp/prometheus-cold-restore-two-host-a
./target/release/prometheus --data /tmp/prometheus-cold-restore-two-host-a init
./target/release/prometheus --data /tmp/prometheus-cold-restore-two-host-a host --listen-address 127.0.0.1:18850
```

Open `http://127.0.0.1:18850/laboratory`.

Add an agent type if the list is empty. Birth an instance if you want a restored live instance. The response returns the holder secret path only. Secret bytes are not returned.

On Laboratory restore:

- Backup path on this host: `/tmp/prometheus-cold-restore-two-host-backup`
- Type the word backup to confirm.
- Write the issuer backup.

The backup path must live outside the data directory. Secret bytes are not returned. Member two is not in the backup.

### 2. Host B empty dest

```
rm -rf /tmp/prometheus-cold-restore-two-host-b
mkdir -p /tmp/prometheus-cold-restore-two-host-b
./target/release/prometheus --data /tmp/prometheus-cold-restore-two-host-b host --listen-address 127.0.0.1:18851
```

Do not init Host B. Empty --data lets restore write.

Open `http://127.0.0.1:18851/laboratory`.

On Laboratory restore:

- Restore from path: `/tmp/prometheus-cold-restore-two-host-backup`
- Type the word restore to confirm.
- Restore onto this empty store.

Expect restore_succeeded and operation_normal.

- Diagnose from path: `/tmp/prometheus-cold-restore-two-host-backup`
- Diagnose restore.

Expect operation_normal.

### 3. Present on B

Refresh the instance list on Host B. A restored live instance is listed.

Present-svid:

- Instance identifier from that list.
- Capability identifier from that list.
- Holder secret path: `/tmp/prometheus-cold-restore-two-host-b/holders/<instance-id>.secret`
- Request a challenge. Then present-svid.

Optional present-wimse uses the same identifiers on the same page.

Secret bytes are not returned.

### 4. Restore on A refuses

On Host A laboratory:

- Restore from path: `/tmp/prometheus-cold-restore-two-host-backup`
- Type the word restore to confirm.
- Restore onto this empty store.

The host refuses. That dest already has an issuer.

### 5. At n=2 dest birth and present refuse without the member path

Use a throwaway member path only. Do not use the VPC. Do not use data-a.

On a throwaway pair at issuance threshold_n 2:

- Register member two at `/tmp/prometheus-cold-restore-two-host-member-two/member-two.secret`
- Set issuer threshold to 2. Confirm is the exact word issuer-threshold.
- Backup again to a new outside /tmp path.
- Restore that backup onto a new empty Host B.
- Birth on dest without the member path refuses.
- Present on dest without the member path refuses.

Birth and present with the same throwaway member-two path succeed. Standing data-a stays n=2. Standing data-a is not the restore dest. Do not raise standing data-a.

## After the walk

Stop both hosts. Remove the /tmp throwaway directories. Do not remove data-a. Do not start SPIRE.

## Whether the walk succeeded

The host-pair tests already prove this walk. `the_cold_restore_two_host_see_walk_restores_presents_and_refuses_a_second_live_issuer` runs the walk through kernel and host helpers. That test does not spawn a long-lived public listener.

## Blocked work

No public bind. No SPIRE. No secrets provider. No sixth record. Standing data-a is not the dest. Restore stays restore.
