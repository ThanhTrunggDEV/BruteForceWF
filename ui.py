"""Hiển thị console: dùng Rich nếu được cài, tự fallback về plain text."""

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    HAVE_RICH = True
    console = Console(highlight=False, soft_wrap=True)
except ImportError:
    HAVE_RICH = False
    console = None


def _line(tag, message, style):
    if console:
        text = Text()
        text.append(f"{tag} ", style=f"bold {style}")
        text.append(str(message))
        console.print(text)
    else:
        print(f"{tag} {message}")


def info(message):
    _line("[*]", message, "cyan")


def warn(message):
    _line("[!]", message, "yellow")


def error(message):
    _line("[x]", message, "red")


def success(message):
    _line("[+]", message, "green")


def fail(message):
    error(message)
    raise SystemExit(1)


def rule(title):
    if console:
        console.print()
        console.rule(Text(str(title), style="bold cyan"), style="cyan")
    else:
        print(f"\n[*] {title}")


def ask(prompt):
    if console:
        return console.input(prompt, markup=False)
    return input(prompt)


def command(line):
    if console:
        text = Text("    $ ", style="dim")
        text.append(str(line), style="bold")
        console.print(text)
    else:
        print(f"    $ {line}")


def stage(message, ok):
    if console:
        text = Text("    ")
        text.append(str(message), style="green" if ok else "yellow")
        console.print(text)
    else:
        print(f"    {message}")


def _signal(pct):
    style = "green" if pct >= 70 else "yellow" if pct >= 40 else "red"
    return Text(f"{pct}%", style=style)


def _security(security):
    upper = security.upper()
    if upper in ("", "OPEN") or "WEP" in upper:
        style = "red"
    elif "WPA2" in upper and "802.1X" not in upper:
        style = "green"
    else:
        style = "yellow"
    return Text(security, style=style)


def scan_table(aps):
    if not console:
        print(f"\n{'STT':>3}  {'':2} {'SSID':<28} {'BSSID':<17} {'KÊNH':>4} {'BAND':>4} {'SIGNAL':>6}  BẢO MẬT")
        print("-" * 94)
        for index, ap in enumerate(aps, 1):
            mark = "*" if ap["in_use"] else " "
            print(
                f"{index:>3}  {mark:2} {ap['ssid'][:28]:<28} {ap['bssid']:<17} "
                f"{ap['chan']:>4} {ap['band']:>4} {ap['signal']:>5}%  {ap['security']}"
            )
        print("-" * 94)
        print("(* = mạng máy đang kết nối)")
        return

    table = Table(box=box.SIMPLE_HEAVY, header_style="bold white", pad_edge=False)
    table.add_column("STT", justify="right", style="dim")
    table.add_column("", width=2)
    table.add_column("SSID", style="bold", max_width=32)
    table.add_column("BSSID", style="dim", no_wrap=True)
    table.add_column("Kênh", justify="right", no_wrap=True)
    table.add_column("Band", justify="right", no_wrap=True)
    table.add_column("Signal", justify="right", no_wrap=True)
    table.add_column("Bảo mật", no_wrap=True)
    for index, ap in enumerate(aps, 1):
        table.add_row(
            str(index),
            Text("●", style="green") if ap["in_use"] else Text(" "),
            Text(ap["ssid"]),
            Text(ap["bssid"]),
            Text(str(ap["chan"])),
            Text(ap["band"]),
            _signal(ap["signal"]),
            _security(ap["security"]),
        )
    console.print()
    console.print(table)
    console.print(Text("● = mạng máy đang kết nối", style="dim"))


def plan(stages, hashcat):
    for index, (label, cmd) in enumerate(stages, 1):
        command_line = " ".join([hashcat] + cmd)
        if console:
            header = Text()
            header.append(f"{index:>2}. ", style="dim")
            header.append(str(label), style="bold")
            console.print(header)
            console.print(Text(f"    $ {command_line}", style="dim"))
        else:
            print(f"{index:>3}. {label}")
            print(f"    $ {command_line}")


def results(found, essids, total):
    if not console:
        print(f"\n[+] ĐÃ BẺ ĐƯỢC {len(found)}/{total} hash")
        for digest, plaintext in found.items():
            print(f"    SSID: {essids.get(digest, '?')}  |  pass: {plaintext}")
        return
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold", pad_edge=False)
    table.add_column("SSID", style="bold")
    table.add_column("Mật khẩu", style="bold green")
    for digest, plaintext in found.items():
        table.add_row(Text(essids.get(digest, "?")), Text(plaintext))
    grid = Table.grid()
    grid.add_row(Text(f"ĐÃ BẺ ĐƯỢC {len(found)}/{total} hash", style="bold green"))
    grid.add_row(table)
    console.print()
    console.print(Panel(
        grid,
        border_style="green",
        title=Text("KẾT QUẢ", style="bold green"),
        title_align="left",
    ))
