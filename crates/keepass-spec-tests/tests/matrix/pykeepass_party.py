#!/usr/bin/env python3
"""pykeepass side of the conformance matrix (driven by pykeepass_party.rs).

Usage: pykeepass_party.py <command>, with a JSON request on stdin:

  version  {}                                      -> prints pykeepass.__version__
  consume  {db, password, keyfile?}                -> prints the database as JSON
  produce  {db, password, keyfile?, entries: [..]} -> writes a new database to db
  edit     {db, password, keyfile?, title, notes}  -> sets notes on the entry with
                                                      that title (adding it to the
                                                      root group if missing) and
                                                      saves in place

`consume` prints {path: {username, password, url, notes, custom_fields, tags,
attachments}}, where path is the group names below root plus the title, joined
with "/", and attachments maps name to lowercase hex.
"""

import json
import sys

import pykeepass
from pykeepass import PyKeePass, create_database
from pykeepass.entry import Entry


def open_db(req):
    return PyKeePass(req["db"], password=req["password"], keyfile=req.get("keyfile"))


def walk(group, prefix, out):
    for e in group.entries:
        path = "/".join(prefix + [e.title or ""])
        out[path] = {
            "username": e.username or "",
            "password": e.password or "",
            "url": e.url or "",
            "notes": e.notes or "",
            "custom_fields": {k: v or "" for k, v in e.custom_properties.items()},
            "tags": sorted(e.tags or []),
            "attachments": {a.filename: (a.binary or b"").hex() for a in e.attachments},
        }
    for g in group.subgroups:
        walk(g, prefix + [g.name], out)


def consume(req):
    out = {}
    walk(open_db(req).root_group, [], out)
    json.dump(out, sys.stdout)


def weaken_kdf(kp):
    """Cheap Argon2 parameters, as the other matrix producers use. pykeepass's
    blank template (64 MiB, 14 passes) is far too slow for a debug-build reader
    opening it in hundreds of cells."""
    params = kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params["I"].value = 1
    params["M"].value = 16 * 1024 * 1024
    params["P"].value = 1


def produce(req):
    kp = create_database(req["db"], password=req["password"], keyfile=req.get("keyfile"))
    weaken_kdf(kp)
    # The matrix compares paths below the root group, and the other producers
    # leave its name empty; keepassxc's CSV export would prefix "Root/".
    kp.root_group.name = ""
    for spec in req["entries"]:
        group = kp.root_group
        for name in spec["group_path"]:
            sub = next((g for g in group.subgroups if g.name == name), None)
            group = sub if sub is not None else kp.add_group(group, name)
        # What kp.add_entry does, minus its duplicate check: that builds an
        # XPath query from the title and username, which breaks on a quote.
        entry = Entry(
            title=spec["title"],
            username=spec["username"],
            password=spec["password"],
            url=spec["url"] or None,
            notes=spec["notes"] or None,
            tags=spec["tags"] or None,
            kp=kp,
        )
        group.append(entry)
        for key, value, protected in spec["custom_fields"]:
            entry.set_custom_property(key, value, protect=protected)
        for name, data in spec["attachments"]:
            entry.add_attachment(kp.add_binary(bytes.fromhex(data)), name)
    kp.save()


def edit(req):
    kp = open_db(req)
    entry = kp.find_entries(title=req["title"], first=True)
    if entry is None:
        entry = kp.add_entry(kp.root_group, req["title"], "", "")
    entry.notes = req["notes"]
    kp.save()


def main():
    command = sys.argv[1]
    req = json.load(sys.stdin)
    if command == "version":
        print(pykeepass.__version__)
    elif command == "consume":
        consume(req)
    elif command == "produce":
        produce(req)
    elif command == "edit":
        edit(req)
    else:
        sys.exit(f"unknown command {command!r}")


if __name__ == "__main__":
    main()
