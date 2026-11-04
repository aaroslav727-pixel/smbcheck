"""Дымовой тест окна без настоящего Tk: подменяем tkinter заглушками и прогоняем сценарии.

Ловит ошибки в нашей логике (опечатки, неверные вызовы storage/scanner), а не в отрисовке.
"""
import importlib
import sys
import types
from unittest.mock import MagicMock

import pytest


class Var:
    def __init__(self, master=None, value=None):
        self.v = value

    def get(self):
        return self.v

    def set(self, v):
        self.v = v


class Text(MagicMock):
    def __init__(self, *a, **k):
        super().__init__()
        self._t = ""

    def insert(self, idx, s):
        self._t += s

    def get(self, *a):
        return self._t + "\n"


class Tree(MagicMock):
    def __init__(self, *a, **k):
        super().__init__()
        self.items, self.sel = [], []

    def delete(self, *ids):
        self.items = [i for i in self.items if i not in ids]

    def get_children(self):
        return list(self.items)

    def insert(self, parent, idx, iid=None, **kw):
        self.items.append(iid)
        return iid

    def selection(self):
        return tuple(self.sel)

    def selection_set(self, ids):
        self.sel = [ids] if isinstance(ids, str) else list(ids)

    def exists(self, i):
        return i in self.items


def W(*a, **k):
    return MagicMock()


def fake_tk():
    tk = types.ModuleType("tkinter")
    tk.StringVar = tk.BooleanVar = Var
    tk.Text = Text
    tk.Misc = object
    tk.Tk = W
    tk.Toplevel = W
    ttk = types.ModuleType("tkinter.ttk")
    for name in ("Frame", "Label", "Entry", "Button", "Checkbutton", "LabelFrame", "Separator",
                 "PanedWindow", "Scrollbar", "Progressbar", "Style", "Combobox"):
        setattr(ttk, name, W)
    ttk.Treeview = Tree
    mb = types.ModuleType("tkinter.messagebox")
    mb.answers = []
    mb.shown = []
    mb.askyesno = lambda *a, **k: mb.answers.pop(0) if mb.answers else True
    mb.showinfo = mb.showwarning = mb.showerror = lambda *a, **k: mb.shown.append(a)
    fd = types.ModuleType("tkinter.filedialog")
    fd.askdirectory = lambda **k: ""
    st = types.ModuleType("tkinter.scrolledtext")
    st.ScrolledText = Text
    tk.ttk, tk.messagebox, tk.filedialog, tk.scrolledtext = ttk, mb, fd, st
    return {"tkinter": tk, "tkinter.ttk": ttk, "tkinter.messagebox": mb,
            "tkinter.filedialog": fd, "tkinter.scrolledtext": st}


@pytest.fixture
def gui(monkeypatch, tmp_path):
    for k, v in fake_tk().items():
        monkeypatch.setitem(sys.modules, k, v)
    monkeypatch.setenv("SMBCHECK_HOME", str(tmp_path))
    sys.modules.pop("smbcheck.gui", None)
    g = importlib.import_module("smbcheck.gui")
    monkeypatch.setattr(g, "open_path", lambda p: g.__dict__.setdefault("_opened", []).append(p))
    yield g
    sys.modules.pop("smbcheck.gui", None)


def test_gui_flow(gui, tmp_path, monkeypatch):
    from smbcheck.storage import Store
    app = gui.App(Store(tmp_path))
    app.root.wait_window = lambda w: None

    # новый клиент без согласия → вопрос «сохранить всё равно?» (да)
    real_init = gui.ClientDialog.__init__

    def fill(dialog_cls, **vals):
        orig = real_init

        def init(self, parent, client, settings):
            orig(self, parent, client, settings)
            for k, v in vals.items():
                attr = getattr(self, k)
                (attr.set(v) if isinstance(attr, Var) else attr.insert("1.0", v))
            self._save()
        return init

    monkeypatch.setattr(gui.ClientDialog, "__init__",
                        fill(gui.ClientDialog, v_name="ООО Тест", v_domain="https://www.Test-Firma.ru/",
                             t_emails="boss@test-firma.ru", t_ips="81.200.10.20"))
    app.add_client()
    assert len(app.clients) == 1
    c = app.clients[0]
    assert c.domain == "test-firma.ru" and c.office_ips == ["81.200.10.20"]

    # проверка без согласия блокируется, сканер не вызывается
    called = []
    monkeypatch.setattr(gui, "run_scan", lambda *a, **k: called.append(1))
    app.tree.selection_set(c.id)
    app.scan_selected()
    assert not called and any("согласия" in str(m) for m in sys.modules["tkinter.messagebox"].shown)

    # добавляем согласие через карточку
    monkeypatch.setattr(gui.ClientDialog, "__init__",
                        fill(gui.ClientDialog, v_has=True, v_cdoc="Договор 1", v_cdate="01.11.2026"))
    app.edit_client()
    assert app.clients[0].consent.problem() == ""

    # проверка в фоне с подменённым сканером
    from smbcheck.demo import demo_results
    res, _ = demo_results()
    monkeypatch.setattr(gui, "run_scan", lambda *a, **k: res)
    app.scan_selected()
    app.worker.join(5)
    app._poll()
    assert c.id in app.last_report and app.last_report[c.id].exists()
    assert app.store.last_scan(c.id).grade == res.grade

    app.copy_text()
    app.root.clipboard_append.assert_called()
    app.open_report()
    app.demo()
    assert len(gui._opened) == 2

    # удаление
    app.delete_client()
    assert app.clients == []


def test_bad_inputs(gui, tmp_path, monkeypatch):
    from smbcheck.storage import Store
    app = gui.App(Store(tmp_path))
    d = gui.ClientDialog(app.root, None, app.settings)
    d.v_name.set("X")
    d.v_domain.set("не домен")
    assert d._collect(strict=True) is None
    d.v_domain.set("x.ru")
    d.t_ips.insert("1.0", "192.168.1.1")
    assert d._collect(strict=True) is None  # внутренний адрес отклоняется


def test_gui_fin_flow(gui, tmp_path, monkeypatch):
    from smbcheck.models import HIGH, Finding, ScanResult
    from smbcheck.storage import Client, Consent, Store
    st = Store(tmp_path)
    st.save_clients([Client("МФО", "tez.uz", consent=Consent(True, "01.11.2026", "", "Д1"), profile="uz_fin")])
    app = gui.App(st)
    app.root.wait_window = lambda w: None
    c = app.clients[0]

    # карточка: тип клиента и доверенные домены сохраняются
    d = gui.ClientDialog(app.root, c, app.settings)
    assert d.v_profile.get().startswith("Финорганизация Узбекистана")
    d.t_trusted.insert("1.0", "https://tez.com/")
    d.v_keywords.set("Tez, TezPay")
    got = d._collect(strict=True)
    assert got.profile == "uz_fin" and got.trusted_domains == ["tez.com"] and got.brand_keywords == ["tez", "tezpay"]

    # быстрая проверка двойников уходит в отдельную историю и готовит черновики уведомлений
    res = ScanResult("tez.uz", finished="2026-11-04T10:00:00", checks_run=["brand"],
                     findings=[Finding("brand.lookalike.tez-pay.uz", "brand", HIGH, "Домен-двойник: tez-pay.uz")])
    seen = []
    monkeypatch.setattr(gui, "run_scan", lambda cl, s, checks, **k: seen.append(checks) or res)
    app.tree.selection_set(c.id)
    app.scan_brand()
    app.worker.join(5)
    app._poll()
    assert seen == [["brand"]]
    assert app.store.last_scan(c.id) is None and app.store.last_with(c.id, "brand") is not None
    assert list((tmp_path / "reports" / "уведомления").glob("*.html"))

    app.evidence()
    app.notices()
    app.demo_fin()
    assert len(gui._opened) == 4
