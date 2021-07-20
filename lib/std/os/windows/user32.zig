// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
usingnamespace @import("bits.zig");
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const windows = @import("../windows.zig");
const unexpectedError = windows.unexpectedError;
const GetLastError = windows.kernel32.GetLastError;
const SetLastError = windows.kernel32.SetLastError;

fn selectSymbol(comptime function_static: anytype, function_dynamic: @TypeOf(function_static), comptime os: std.Target.Os.WindowsVersion) @TypeOf(function_static) {
    comptime {
        const sym_ok = builtin.os.isAtLeast(.windows, os);
        if (sym_ok == true) return function_static;
        if (sym_ok == null) return function_dynamic;
        if (sym_ok == false) @compileError("Target OS range does not support function, at least " ++ @tagName(os) ++ " is required");
    }
}

// === Messages ===

pub const WNDPROC = fn (hwnd: HWND, uMsg: UINT, wParam: WPARAM, lParam: LPARAM) callconv(WINAPI) LRESULT;

pub const MSG = extern struct {
    hWnd: ?HWND,
    message: UINT,
    wParam: WPARAM,
    lParam: LPARAM,
    time: DWORD,
    pt: POINT,
    lPrivate: DWORD,
};

// Compiled by the WINE team @ https://wiki.winehq.org/List_Of_Windows_Messages
pub const WM_NULL = 0x0000;
pub const WM_CREATE = 0x0001;
pub const WM_DESTROY = 0x0002;
pub const WM_MOVE = 0x0003;
pub const WM_SIZE = 0x0005;
pub const WM_ACTIVATE = 0x0006;
pub const WM_SETFOCUS = 0x0007;
pub const WM_KILLFOCUS = 0x0008;
pub const WM_ENABLE = 0x000A;
pub const WM_SETREDRAW = 0x000B;
pub const WM_SETTEXT = 0x000C;
pub const WM_GETTEXT = 0x000D;
pub const WM_GETTEXTLENGTH = 0x000E;
pub const WM_PAINT = 0x000F;
pub const WM_CLOSE = 0x0010;
pub const WM_QUERYENDSESSION = 0x0011;
pub const WM_QUIT = 0x0012;
pub const WM_QUERYOPEN = 0x0013;
pub const WM_ERASEBKGND = 0x0014;
pub const WM_SYSCOLORCHANGE = 0x0015;
pub const WM_ENDSESSION = 0x0016;
pub const WM_SHOWWINDOW = 0x0018;
pub const WM_CTLCOLOR = 0x0019;
pub const WM_WININICHANGE = 0x001A;
pub const WM_DEVMODECHANGE = 0x001B;
pub const WM_ACTIVATEAPP = 0x001C;
pub const WM_FONTCHANGE = 0x001D;
pub const WM_TIMECHANGE = 0x001E;
pub const WM_CANCELMODE = 0x001F;
pub const WM_SETCURSOR = 0x0020;
pub const WM_MOUSEACTIVATE = 0x0021;
pub const WM_CHILDACTIVATE = 0x0022;
pub const WM_QUEUESYNC = 0x0023;
pub const WM_GETMINMAXINFO = 0x0024;
pub const WM_PAINTICON = 0x0026;
pub const WM_ICONERASEBKGND = 0x0027;
pub const WM_NEXTDLGCTL = 0x0028;
pub const WM_SPOOLERSTATUS = 0x002A;
pub const WM_DRAWITEM = 0x002B;
pub const WM_MEASUREITEM = 0x002C;
pub const WM_DELETEITEM = 0x002D;
pub const WM_VKEYTOITEM = 0x002E;
pub const WM_CHARTOITEM = 0x002F;
pub const WM_SETFONT = 0x0030;
pub const WM_GETFONT = 0x0031;
pub const WM_SETHOTKEY = 0x0032;
pub const WM_GETHOTKEY = 0x0033;
pub const WM_QUERYDRAGICON = 0x0037;
pub const WM_COMPAREITEM = 0x0039;
pub const WM_GETOBJECT = 0x003D;
pub const WM_COMPACTING = 0x0041;
pub const WM_COMMNOTIFY = 0x0044;
pub const WM_WINDOWPOSCHANGING = 0x0046;
pub const WM_WINDOWPOSCHANGED = 0x0047;
pub const WM_POWER = 0x0048;
pub const WM_COPYGLOBALDATA = 0x0049;
pub const WM_COPYDATA = 0x004A;
pub const WM_CANCELJOURNAL = 0x004B;
pub const WM_NOTIFY = 0x004E;
pub const WM_INPUTLANGCHANGEREQUEST = 0x0050;
pub const WM_INPUTLANGCHANGE = 0x0051;
pub const WM_TCARD = 0x0052;
pub const WM_HELP = 0x0053;
pub const WM_USERCHANGED = 0x0054;
pub const WM_NOTIFYFORMAT = 0x0055;
pub const WM_CONTEXTMENU = 0x007B;
pub const WM_STYLECHANGING = 0x007C;
pub const WM_STYLECHANGED = 0x007D;
pub const WM_DISPLAYCHANGE = 0x007E;
pub const WM_GETICON = 0x007F;
pub const WM_SETICON = 0x0080;
pub const WM_NCCREATE = 0x0081;
pub const WM_NCDESTROY = 0x0082;
pub const WM_NCCALCSIZE = 0x0083;
pub const WM_NCHITTEST = 0x0084;
pub const WM_NCPAINT = 0x0085;
pub const WM_NCACTIVATE = 0x0086;
pub const WM_GETDLGCODE = 0x0087;
pub const WM_SYNCPAINT = 0x0088;
pub const WM_NCMOUSEMOVE = 0x00A0;
pub const WM_NCLBUTTONDOWN = 0x00A1;
pub const WM_NCLBUTTONUP = 0x00A2;
pub const WM_NCLBUTTONDBLCLK = 0x00A3;
pub const WM_NCRBUTTONDOWN = 0x00A4;
pub const WM_NCRBUTTONUP = 0x00A5;
pub const WM_NCRBUTTONDBLCLK = 0x00A6;
pub const WM_NCMBUTTONDOWN = 0x00A7;
pub const WM_NCMBUTTONUP = 0x00A8;
pub const WM_NCMBUTTONDBLCLK = 0x00A9;
pub const WM_NCXBUTTONDOWN = 0x00AB;
pub const WM_NCXBUTTONUP = 0x00AC;
pub const WM_NCXBUTTONDBLCLK = 0x00AD;
pub const EM_GETSEL = 0x00B0;
pub const EM_SETSEL = 0x00B1;
pub const EM_GETRECT = 0x00B2;
pub const EM_SETRECT = 0x00B3;
pub const EM_SETRECTNP = 0x00B4;
pub const EM_SCROLL = 0x00B5;
pub const EM_LINESCROLL = 0x00B6;
pub const EM_SCROLLCARET = 0x00B7;
pub const EM_GETMODIFY = 0x00B8;
pub const EM_SETMODIFY = 0x00B9;
pub const EM_GETLINECOUNT = 0x00BA;
pub const EM_LINEINDEX = 0x00BB;
pub const EM_SETHANDLE = 0x00BC;
pub const EM_GETHANDLE = 0x00BD;
pub const EM_GETTHUMB = 0x00BE;
pub const EM_LINELENGTH = 0x00C1;
pub const EM_REPLACESEL = 0x00C2;
pub const EM_SETFONT = 0x00C3;
pub const EM_GETLINE = 0x00C4;
pub const EM_LIMITTEXT = 0x00C5;
pub const EM_SETLIMITTEXT = 0x00C5;
pub const EM_CANUNDO = 0x00C6;
pub const EM_UNDO = 0x00C7;
pub const EM_FMTLINES = 0x00C8;
pub const EM_LINEFROMCHAR = 0x00C9;
pub const EM_SETWORDBREAK = 0x00CA;
pub const EM_SETTABSTOPS = 0x00CB;
pub const EM_SETPASSWORDCHAR = 0x00CC;
pub const EM_EMPTYUNDOBUFFER = 0x00CD;
pub const EM_GETFIRSTVISIBLELINE = 0x00CE;
pub const EM_SETREADONLY = 0x00CF;
pub const EM_SETWORDBREAKPROC = 0x00D0;
pub const EM_GETWORDBREAKPROC = 0x00D1;
pub const EM_GETPASSWORDCHAR = 0x00D2;
pub const EM_SETMARGINS = 0x00D3;
pub const EM_GETMARGINS = 0x00D4;
pub const EM_GETLIMITTEXT = 0x00D5;
pub const EM_POSFROMCHAR = 0x00D6;
pub const EM_CHARFROMPOS = 0x00D7;
pub const EM_SETIMESTATUS = 0x00D8;
pub const EM_GETIMESTATUS = 0x00D9;
pub const SBM_SETPOS = 0x00E0;
pub const SBM_GETPOS = 0x00E1;
pub const SBM_SETRANGE = 0x00E2;
pub const SBM_GETRANGE = 0x00E3;
pub const SBM_ENABLE_ARROWS = 0x00E4;
pub const SBM_SETRANGEREDRAW = 0x00E6;
pub const SBM_SETSCROLLINFO = 0x00E9;
pub const SBM_GETSCROLLINFO = 0x00EA;
pub const SBM_GETSCROLLBARINFO = 0x00EB;
pub const BM_GETCHECK = 0x00F0;
pub const BM_SETCHECK = 0x00F1;
pub const BM_GETSTATE = 0x00F2;
pub const BM_SETSTATE = 0x00F3;
pub const BM_SETSTYLE = 0x00F4;
pub const BM_CLICK = 0x00F5;
pub const BM_GETIMAGE = 0x00F6;
pub const BM_SETIMAGE = 0x00F7;
pub const BM_SETDONTCLICK = 0x00F8;
pub const WM_INPUT = 0x00FF;
pub const WM_KEYDOWN = 0x0100;
pub const WM_KEYUP = 0x0101;
pub const WM_CHAR = 0x0102;
pub const WM_DEADCHAR = 0x0103;
pub const WM_SYSKEYDOWN = 0x0104;
pub const WM_SYSKEYUP = 0x0105;
pub const WM_SYSCHAR = 0x0106;
pub const WM_SYSDEADCHAR = 0x0107;
pub const WM_UNICHAR = 0x0109;
pub const WM_WNT_CONVERTREQUESTEX = 0x0109;
pub const WM_CONVERTREQUEST = 0x010A;
pub const WM_CONVERTRESULT = 0x010B;
pub const WM_INTERIM = 0x010C;
pub const WM_IME_STARTCOMPOSITION = 0x010D;
pub const WM_IME_ENDCOMPOSITION = 0x010E;
pub const WM_IME_COMPOSITION = 0x010F;
pub const WM_INITDIALOG = 0x0110;
pub const WM_COMMAND = 0x0111;
pub const WM_SYSCOMMAND = 0x0112;
pub const WM_TIMER = 0x0113;
pub const WM_HSCROLL = 0x0114;
pub const WM_VSCROLL = 0x0115;
pub const WM_INITMENU = 0x0116;
pub const WM_INITMENUPOPUP = 0x0117;
pub const WM_SYSTIMER = 0x0118;
pub const WM_MENUSELECT = 0x011F;
pub const WM_MENUCHAR = 0x0120;
pub const WM_ENTERIDLE = 0x0121;
pub const WM_MENURBUTTONUP = 0x0122;
pub const WM_MENUDRAG = 0x0123;
pub const WM_MENUGETOBJECT = 0x0124;
pub const WM_UNINITMENUPOPUP = 0x0125;
pub const WM_MENUCOMMAND = 0x0126;
pub const WM_CHANGEUISTATE = 0x0127;
pub const WM_UPDATEUISTATE = 0x0128;
pub const WM_QUERYUISTATE = 0x0129;
pub const WM_CTLCOLORMSGBOX = 0x0132;
pub const WM_CTLCOLOREDIT = 0x0133;
pub const WM_CTLCOLORLISTBOX = 0x0134;
pub const WM_CTLCOLORBTN = 0x0135;
pub const WM_CTLCOLORDLG = 0x0136;
pub const WM_CTLCOLORSCROLLBAR = 0x0137;
pub const WM_CTLCOLORSTATIC = 0x0138;
pub const WM_MOUSEMOVE = 0x0200;
pub const WM_LBUTTONDOWN = 0x0201;
pub const WM_LBUTTONUP = 0x0202;
pub const WM_LBUTTONDBLCLK = 0x0203;
pub const WM_RBUTTONDOWN = 0x0204;
pub const WM_RBUTTONUP = 0x0205;
pub const WM_RBUTTONDBLCLK = 0x0206;
pub const WM_MBUTTONDOWN = 0x0207;
pub const WM_MBUTTONUP = 0x0208;
pub const WM_MBUTTONDBLCLK = 0x0209;
pub const WM_MOUSEWHEEL = 0x020A;
pub const WM_XBUTTONDOWN = 0x020B;
pub const WM_XBUTTONUP = 0x020C;
pub const WM_XBUTTONDBLCLK = 0x020D;
pub const WM_MOUSEHWHEEL = 0x020E;
pub const WM_PARENTNOTIFY = 0x0210;
pub const WM_ENTERMENULOOP = 0x0211;
pub const WM_EXITMENULOOP = 0x0212;
pub const WM_NEXTMENU = 0x0213;
pub const WM_SIZING = 0x0214;
pub const WM_CAPTURECHANGED = 0x0215;
pub const WM_MOVING = 0x0216;
pub const WM_POWERBROADCAST = 0x0218;
pub const WM_DEVICECHANGE = 0x0219;
pub const WM_MDICREATE = 0x0220;
pub const WM_MDIDESTROY = 0x0221;
pub const WM_MDIACTIVATE = 0x0222;
pub const WM_MDIRESTORE = 0x0223;
pub const WM_MDINEXT = 0x0224;
pub const WM_MDIMAXIMIZE = 0x0225;
pub const WM_MDITILE = 0x0226;
pub const WM_MDICASCADE = 0x0227;
pub const WM_MDIICONARRANGE = 0x0228;
pub const WM_MDIGETACTIVE = 0x0229;
pub const WM_MDISETMENU = 0x0230;
pub const WM_ENTERSIZEMOVE = 0x0231;
pub const WM_EXITSIZEMOVE = 0x0232;
pub const WM_DROPFILES = 0x0233;
pub const WM_MDIREFRESHMENU = 0x0234;
pub const WM_IME_REPORT = 0x0280;
pub const WM_IME_SETCONTEXT = 0x0281;
pub const WM_IME_NOTIFY = 0x0282;
pub const WM_IME_CONTROL = 0x0283;
pub const WM_IME_COMPOSITIONFULL = 0x0284;
pub const WM_IME_SELECT = 0x0285;
pub const WM_IME_CHAR = 0x0286;
pub const WM_IME_REQUEST = 0x0288;
pub const WM_IMEKEYDOWN = 0x0290;
pub const WM_IME_KEYDOWN = 0x0290;
pub const WM_IMEKEYUP = 0x0291;
pub const WM_IME_KEYUP = 0x0291;
pub const WM_NCMOUSEHOVER = 0x02A0;
pub const WM_MOUSEHOVER = 0x02A1;
pub const WM_NCMOUSELEAVE = 0x02A2;
pub const WM_MOUSELEAVE = 0x02A3;
pub const WM_CUT = 0x0300;
pub const WM_COPY = 0x0301;
pub const WM_PASTE = 0x0302;
pub const WM_CLEAR = 0x0303;
pub const WM_UNDO = 0x0304;
pub const WM_RENDERFORMAT = 0x0305;
pub const WM_RENDERALLFORMATS = 0x0306;
pub const WM_DESTROYCLIPBOARD = 0x0307;
pub const WM_DRAWCLIPBOARD = 0x0308;
pub const WM_PAINTCLIPBOARD = 0x0309;
pub const WM_VSCROLLCLIPBOARD = 0x030A;
pub const WM_SIZECLIPBOARD = 0x030B;
pub const WM_ASKCBFORMATNAME = 0x030C;
pub const WM_CHANGECBCHAIN = 0x030D;
pub const WM_HSCROLLCLIPBOARD = 0x030E;
pub const WM_QUERYNEWPALETTE = 0x030F;
pub const WM_PALETTEISCHANGING = 0x0310;
pub const WM_PALETTECHANGED = 0x0311;
pub const WM_HOTKEY = 0x0312;
pub const WM_PRINT = 0x0317;
pub const WM_PRINTCLIENT = 0x0318;
pub const WM_APPCOMMAND = 0x0319;
pub const WM_RCRESULT = 0x0381;
pub const WM_HOOKRCRESULT = 0x0382;
pub const WM_GLOBALRCCHANGE = 0x0383;
pub const WM_PENMISCINFO = 0x0383;
pub const WM_SKB = 0x0384;
pub const WM_HEDITCTL = 0x0385;
pub const WM_PENCTL = 0x0385;
pub const WM_PENMISC = 0x0386;
pub const WM_CTLINIT = 0x0387;
pub const WM_PENEVENT = 0x0388;
pub const WM_CARET_CREATE = 0x03E0;
pub const WM_CARET_DESTROY = 0x03E1;
pub const WM_CARET_BLINK = 0x03E2;
pub const WM_FDINPUT = 0x03F0;
pub const WM_FDOUTPUT = 0x03F1;
pub const WM_FDEXCEPT = 0x03F2;
pub const DDM_SETFMT = 0x0400;
pub const DM_GETDEFID = 0x0400;
pub const NIN_SELECT = 0x0400;
pub const TBM_GETPOS = 0x0400;
pub const WM_PSD_PAGESETUPDLG = 0x0400;
pub const WM_USER = 0x0400;
pub const CBEM_INSERTITEMA = 0x0401;
pub const DDM_DRAW = 0x0401;
pub const DM_SETDEFID = 0x0401;
pub const HKM_SETHOTKEY = 0x0401;
pub const PBM_SETRANGE = 0x0401;
pub const RB_INSERTBANDA = 0x0401;
pub const SB_SETTEXTA = 0x0401;
pub const TB_ENABLEBUTTON = 0x0401;
pub const TBM_GETRANGEMIN = 0x0401;
pub const TTM_ACTIVATE = 0x0401;
pub const WM_CHOOSEFONT_GETLOGFONT = 0x0401;
pub const WM_PSD_FULLPAGERECT = 0x0401;
pub const CBEM_SETIMAGELIST = 0x0402;
pub const DDM_CLOSE = 0x0402;
pub const DM_REPOSITION = 0x0402;
pub const HKM_GETHOTKEY = 0x0402;
pub const PBM_SETPOS = 0x0402;
pub const RB_DELETEBAND = 0x0402;
pub const SB_GETTEXTA = 0x0402;
pub const TB_CHECKBUTTON = 0x0402;
pub const TBM_GETRANGEMAX = 0x0402;
pub const WM_PSD_MINMARGINRECT = 0x0402;
pub const CBEM_GETIMAGELIST = 0x0403;
pub const DDM_BEGIN = 0x0403;
pub const HKM_SETRULES = 0x0403;
pub const PBM_DELTAPOS = 0x0403;
pub const RB_GETBARINFO = 0x0403;
pub const SB_GETTEXTLENGTHA = 0x0403;
pub const TBM_GETTIC = 0x0403;
pub const TB_PRESSBUTTON = 0x0403;
pub const TTM_SETDELAYTIME = 0x0403;
pub const WM_PSD_MARGINRECT = 0x0403;
pub const CBEM_GETITEMA = 0x0404;
pub const DDM_END = 0x0404;
pub const PBM_SETSTEP = 0x0404;
pub const RB_SETBARINFO = 0x0404;
pub const SB_SETPARTS = 0x0404;
pub const TB_HIDEBUTTON = 0x0404;
pub const TBM_SETTIC = 0x0404;
pub const TTM_ADDTOOLA = 0x0404;
pub const WM_PSD_GREEKTEXTRECT = 0x0404;
pub const CBEM_SETITEMA = 0x0405;
pub const PBM_STEPIT = 0x0405;
pub const TB_INDETERMINATE = 0x0405;
pub const TBM_SETPOS = 0x0405;
pub const TTM_DELTOOLA = 0x0405;
pub const WM_PSD_ENVSTAMPRECT = 0x0405;
pub const CBEM_GETCOMBOCONTROL = 0x0406;
pub const PBM_SETRANGE32 = 0x0406;
pub const RB_SETBANDINFOA = 0x0406;
pub const SB_GETPARTS = 0x0406;
pub const TB_MARKBUTTON = 0x0406;
pub const TBM_SETRANGE = 0x0406;
pub const TTM_NEWTOOLRECTA = 0x0406;
pub const WM_PSD_YAFULLPAGERECT = 0x0406;
pub const CBEM_GETEDITCONTROL = 0x0407;
pub const PBM_GETRANGE = 0x0407;
pub const RB_SETPARENT = 0x0407;
pub const SB_GETBORDERS = 0x0407;
pub const TBM_SETRANGEMIN = 0x0407;
pub const TTM_RELAYEVENT = 0x0407;
pub const CBEM_SETEXSTYLE = 0x0408;
pub const PBM_GETPOS = 0x0408;
pub const RB_HITTEST = 0x0408;
pub const SB_SETMINHEIGHT = 0x0408;
pub const TBM_SETRANGEMAX = 0x0408;
pub const TTM_GETTOOLINFOA = 0x0408;
pub const CBEM_GETEXSTYLE = 0x0409;
pub const CBEM_GETEXTENDEDSTYLE = 0x0409;
pub const PBM_SETBARCOLOR = 0x0409;
pub const RB_GETRECT = 0x0409;
pub const SB_SIMPLE = 0x0409;
pub const TB_ISBUTTONENABLED = 0x0409;
pub const TBM_CLEARTICS = 0x0409;
pub const TTM_SETTOOLINFOA = 0x0409;
pub const CBEM_HASEDITCHANGED = 0x040A;
pub const RB_INSERTBANDW = 0x040A;
pub const SB_GETRECT = 0x040A;
pub const TB_ISBUTTONCHECKED = 0x040A;
pub const TBM_SETSEL = 0x040A;
pub const TTM_HITTESTA = 0x040A;
pub const WIZ_QUERYNUMPAGES = 0x040A;
pub const CBEM_INSERTITEMW = 0x040B;
pub const RB_SETBANDINFOW = 0x040B;
pub const SB_SETTEXTW = 0x040B;
pub const TB_ISBUTTONPRESSED = 0x040B;
pub const TBM_SETSELSTART = 0x040B;
pub const TTM_GETTEXTA = 0x040B;
pub const WIZ_NEXT = 0x040B;
pub const CBEM_SETITEMW = 0x040C;
pub const RB_GETBANDCOUNT = 0x040C;
pub const SB_GETTEXTLENGTHW = 0x040C;
pub const TB_ISBUTTONHIDDEN = 0x040C;
pub const TBM_SETSELEND = 0x040C;
pub const TTM_UPDATETIPTEXTA = 0x040C;
pub const WIZ_PREV = 0x040C;
pub const CBEM_GETITEMW = 0x040D;
pub const RB_GETROWCOUNT = 0x040D;
pub const SB_GETTEXTW = 0x040D;
pub const TB_ISBUTTONINDETERMINATE = 0x040D;
pub const TTM_GETTOOLCOUNT = 0x040D;
pub const CBEM_SETEXTENDEDSTYLE = 0x040E;
pub const RB_GETROWHEIGHT = 0x040E;
pub const SB_ISSIMPLE = 0x040E;
pub const TB_ISBUTTONHIGHLIGHTED = 0x040E;
pub const TBM_GETPTICS = 0x040E;
pub const TTM_ENUMTOOLSA = 0x040E;
pub const SB_SETICON = 0x040F;
pub const TBM_GETTICPOS = 0x040F;
pub const TTM_GETCURRENTTOOLA = 0x040F;
pub const RB_IDTOINDEX = 0x0410;
pub const SB_SETTIPTEXTA = 0x0410;
pub const TBM_GETNUMTICS = 0x0410;
pub const TTM_WINDOWFROMPOINT = 0x0410;
pub const RB_GETTOOLTIPS = 0x0411;
pub const SB_SETTIPTEXTW = 0x0411;
pub const TBM_GETSELSTART = 0x0411;
pub const TB_SETSTATE = 0x0411;
pub const TTM_TRACKACTIVATE = 0x0411;
pub const RB_SETTOOLTIPS = 0x0412;
pub const SB_GETTIPTEXTA = 0x0412;
pub const TB_GETSTATE = 0x0412;
pub const TBM_GETSELEND = 0x0412;
pub const TTM_TRACKPOSITION = 0x0412;
pub const RB_SETBKCOLOR = 0x0413;
pub const SB_GETTIPTEXTW = 0x0413;
pub const TB_ADDBITMAP = 0x0413;
pub const TBM_CLEARSEL = 0x0413;
pub const TTM_SETTIPBKCOLOR = 0x0413;
pub const RB_GETBKCOLOR = 0x0414;
pub const SB_GETICON = 0x0414;
pub const TB_ADDBUTTONSA = 0x0414;
pub const TBM_SETTICFREQ = 0x0414;
pub const TTM_SETTIPTEXTCOLOR = 0x0414;
pub const RB_SETTEXTCOLOR = 0x0415;
pub const TB_INSERTBUTTONA = 0x0415;
pub const TBM_SETPAGESIZE = 0x0415;
pub const TTM_GETDELAYTIME = 0x0415;
pub const RB_GETTEXTCOLOR = 0x0416;
pub const TB_DELETEBUTTON = 0x0416;
pub const TBM_GETPAGESIZE = 0x0416;
pub const TTM_GETTIPBKCOLOR = 0x0416;
pub const RB_SIZETORECT = 0x0417;
pub const TB_GETBUTTON = 0x0417;
pub const TBM_SETLINESIZE = 0x0417;
pub const TTM_GETTIPTEXTCOLOR = 0x0417;
pub const RB_BEGINDRAG = 0x0418;
pub const TB_BUTTONCOUNT = 0x0418;
pub const TBM_GETLINESIZE = 0x0418;
pub const TTM_SETMAXTIPWIDTH = 0x0418;
pub const RB_ENDDRAG = 0x0419;
pub const TB_COMMANDTOINDEX = 0x0419;
pub const TBM_GETTHUMBRECT = 0x0419;
pub const TTM_GETMAXTIPWIDTH = 0x0419;
pub const RB_DRAGMOVE = 0x041A;
pub const TBM_GETCHANNELRECT = 0x041A;
pub const TB_SAVERESTOREA = 0x041A;
pub const TTM_SETMARGIN = 0x041A;
pub const RB_GETBARHEIGHT = 0x041B;
pub const TB_CUSTOMIZE = 0x041B;
pub const TBM_SETTHUMBLENGTH = 0x041B;
pub const TTM_GETMARGIN = 0x041B;
pub const RB_GETBANDINFOW = 0x041C;
pub const TB_ADDSTRINGA = 0x041C;
pub const TBM_GETTHUMBLENGTH = 0x041C;
pub const TTM_POP = 0x041C;
pub const RB_GETBANDINFOA = 0x041D;
pub const TB_GETITEMRECT = 0x041D;
pub const TBM_SETTOOLTIPS = 0x041D;
pub const TTM_UPDATE = 0x041D;
pub const RB_MINIMIZEBAND = 0x041E;
pub const TB_BUTTONSTRUCTSIZE = 0x041E;
pub const TBM_GETTOOLTIPS = 0x041E;
pub const TTM_GETBUBBLESIZE = 0x041E;
pub const RB_MAXIMIZEBAND = 0x041F;
pub const TBM_SETTIPSIDE = 0x041F;
pub const TB_SETBUTTONSIZE = 0x041F;
pub const TTM_ADJUSTRECT = 0x041F;
pub const TBM_SETBUDDY = 0x0420;
pub const TB_SETBITMAPSIZE = 0x0420;
pub const TTM_SETTITLEA = 0x0420;
pub const MSG_FTS_JUMP_VA = 0x0421;
pub const TB_AUTOSIZE = 0x0421;
pub const TBM_GETBUDDY = 0x0421;
pub const TTM_SETTITLEW = 0x0421;
pub const RB_GETBANDBORDERS = 0x0422;
pub const MSG_FTS_JUMP_QWORD = 0x0423;
pub const RB_SHOWBAND = 0x0423;
pub const TB_GETTOOLTIPS = 0x0423;
pub const MSG_REINDEX_REQUEST = 0x0424;
pub const TB_SETTOOLTIPS = 0x0424;
pub const MSG_FTS_WHERE_IS_IT = 0x0425;
pub const RB_SETPALETTE = 0x0425;
pub const TB_SETPARENT = 0x0425;
pub const RB_GETPALETTE = 0x0426;
pub const RB_MOVEBAND = 0x0427;
pub const TB_SETROWS = 0x0427;
pub const TB_GETROWS = 0x0428;
pub const TB_GETBITMAPFLAGS = 0x0429;
pub const TB_SETCMDID = 0x042A;
pub const RB_PUSHCHEVRON = 0x042B;
pub const TB_CHANGEBITMAP = 0x042B;
pub const TB_GETBITMAP = 0x042C;
pub const MSG_GET_DEFFONT = 0x042D;
pub const TB_GETBUTTONTEXTA = 0x042D;
pub const TB_REPLACEBITMAP = 0x042E;
pub const TB_SETINDENT = 0x042F;
pub const TB_SETIMAGELIST = 0x0430;
pub const TB_GETIMAGELIST = 0x0431;
pub const TB_LOADIMAGES = 0x0432;
pub const EM_CANPASTE = 0x0432;
pub const TTM_ADDTOOLW = 0x0432;
pub const EM_DISPLAYBAND = 0x0433;
pub const TB_GETRECT = 0x0433;
pub const TTM_DELTOOLW = 0x0433;
pub const EM_EXGETSEL = 0x0434;
pub const TB_SETHOTIMAGELIST = 0x0434;
pub const TTM_NEWTOOLRECTW = 0x0434;
pub const EM_EXLIMITTEXT = 0x0435;
pub const TB_GETHOTIMAGELIST = 0x0435;
pub const TTM_GETTOOLINFOW = 0x0435;
pub const EM_EXLINEFROMCHAR = 0x0436;
pub const TB_SETDISABLEDIMAGELIST = 0x0436;
pub const TTM_SETTOOLINFOW = 0x0436;
pub const EM_EXSETSEL = 0x0437;
pub const TB_GETDISABLEDIMAGELIST = 0x0437;
pub const TTM_HITTESTW = 0x0437;
pub const EM_FINDTEXT = 0x0438;
pub const TB_SETSTYLE = 0x0438;
pub const TTM_GETTEXTW = 0x0438;
pub const EM_FORMATRANGE = 0x0439;
pub const TB_GETSTYLE = 0x0439;
pub const TTM_UPDATETIPTEXTW = 0x0439;
pub const EM_GETCHARFORMAT = 0x043A;
pub const TB_GETBUTTONSIZE = 0x043A;
pub const TTM_ENUMTOOLSW = 0x043A;
pub const EM_GETEVENTMASK = 0x043B;
pub const TB_SETBUTTONWIDTH = 0x043B;
pub const TTM_GETCURRENTTOOLW = 0x043B;
pub const EM_GETOLEINTERFACE = 0x043C;
pub const TB_SETMAXTEXTROWS = 0x043C;
pub const EM_GETPARAFORMAT = 0x043D;
pub const TB_GETTEXTROWS = 0x043D;
pub const EM_GETSELTEXT = 0x043E;
pub const TB_GETOBJECT = 0x043E;
pub const EM_HIDESELECTION = 0x043F;
pub const TB_GETBUTTONINFOW = 0x043F;
pub const EM_PASTESPECIAL = 0x0440;
pub const TB_SETBUTTONINFOW = 0x0440;
pub const EM_REQUESTRESIZE = 0x0441;
pub const TB_GETBUTTONINFOA = 0x0441;
pub const EM_SELECTIONTYPE = 0x0442;
pub const TB_SETBUTTONINFOA = 0x0442;
pub const EM_SETBKGNDCOLOR = 0x0443;
pub const TB_INSERTBUTTONW = 0x0443;
pub const EM_SETCHARFORMAT = 0x0444;
pub const TB_ADDBUTTONSW = 0x0444;
pub const EM_SETEVENTMASK = 0x0445;
pub const TB_HITTEST = 0x0445;
pub const EM_SETOLECALLBACK = 0x0446;
pub const TB_SETDRAWTEXTFLAGS = 0x0446;
pub const EM_SETPARAFORMAT = 0x0447;
pub const TB_GETHOTITEM = 0x0447;
pub const EM_SETTARGETDEVICE = 0x0448;
pub const TB_SETHOTITEM = 0x0448;
pub const EM_STREAMIN = 0x0449;
pub const TB_SETANCHORHIGHLIGHT = 0x0449;
pub const EM_STREAMOUT = 0x044A;
pub const TB_GETANCHORHIGHLIGHT = 0x044A;
pub const EM_GETTEXTRANGE = 0x044B;
pub const TB_GETBUTTONTEXTW = 0x044B;
pub const EM_FINDWORDBREAK = 0x044C;
pub const TB_SAVERESTOREW = 0x044C;
pub const EM_SETOPTIONS = 0x044D;
pub const TB_ADDSTRINGW = 0x044D;
pub const EM_GETOPTIONS = 0x044E;
pub const TB_MAPACCELERATORA = 0x044E;
pub const EM_FINDTEXTEX = 0x044F;
pub const TB_GETINSERTMARK = 0x044F;
pub const EM_GETWORDBREAKPROCEX = 0x0450;
pub const TB_SETINSERTMARK = 0x0450;
pub const EM_SETWORDBREAKPROCEX = 0x0451;
pub const TB_INSERTMARKHITTEST = 0x0451;
pub const EM_SETUNDOLIMIT = 0x0452;
pub const TB_MOVEBUTTON = 0x0452;
pub const TB_GETMAXSIZE = 0x0453;
pub const EM_REDO = 0x0454;
pub const TB_SETEXTENDEDSTYLE = 0x0454;
pub const EM_CANREDO = 0x0455;
pub const TB_GETEXTENDEDSTYLE = 0x0455;
pub const EM_GETUNDONAME = 0x0456;
pub const TB_GETPADDING = 0x0456;
pub const EM_GETREDONAME = 0x0457;
pub const TB_SETPADDING = 0x0457;
pub const EM_STOPGROUPTYPING = 0x0458;
pub const TB_SETINSERTMARKCOLOR = 0x0458;
pub const EM_SETTEXTMODE = 0x0459;
pub const TB_GETINSERTMARKCOLOR = 0x0459;
pub const EM_GETTEXTMODE = 0x045A;
pub const TB_MAPACCELERATORW = 0x045A;
pub const EM_AUTOURLDETECT = 0x045B;
pub const TB_GETSTRINGW = 0x045B;
pub const EM_GETAUTOURLDETECT = 0x045C;
pub const TB_GETSTRINGA = 0x045C;
pub const EM_SETPALETTE = 0x045D;
pub const EM_GETTEXTEX = 0x045E;
pub const EM_GETTEXTLENGTHEX = 0x045F;
pub const EM_SHOWSCROLLBAR = 0x0460;
pub const EM_SETTEXTEX = 0x0461;
pub const TAPI_REPLY = 0x0463;
pub const ACM_OPENA = 0x0464;
pub const BFFM_SETSTATUSTEXTA = 0x0464;
pub const CDM_GETSPEC = 0x0464;
pub const EM_SETPUNCTUATION = 0x0464;
pub const IPM_CLEARADDRESS = 0x0464;
pub const WM_CAP_UNICODE_START = 0x0464;
pub const ACM_PLAY = 0x0465;
pub const BFFM_ENABLEOK = 0x0465;
pub const CDM_GETFILEPATH = 0x0465;
pub const EM_GETPUNCTUATION = 0x0465;
pub const IPM_SETADDRESS = 0x0465;
pub const PSM_SETCURSEL = 0x0465;
pub const UDM_SETRANGE = 0x0465;
pub const WM_CHOOSEFONT_SETLOGFONT = 0x0465;
pub const ACM_STOP = 0x0466;
pub const BFFM_SETSELECTIONA = 0x0466;
pub const CDM_GETFOLDERPATH = 0x0466;
pub const EM_SETWORDWRAPMODE = 0x0466;
pub const IPM_GETADDRESS = 0x0466;
pub const PSM_REMOVEPAGE = 0x0466;
pub const UDM_GETRANGE = 0x0466;
pub const WM_CAP_SET_CALLBACK_ERRORW = 0x0466;
pub const WM_CHOOSEFONT_SETFLAGS = 0x0466;
pub const ACM_OPENW = 0x0467;
pub const BFFM_SETSELECTIONW = 0x0467;
pub const CDM_GETFOLDERIDLIST = 0x0467;
pub const EM_GETWORDWRAPMODE = 0x0467;
pub const IPM_SETRANGE = 0x0467;
pub const PSM_ADDPAGE = 0x0467;
pub const UDM_SETPOS = 0x0467;
pub const WM_CAP_SET_CALLBACK_STATUSW = 0x0467;
pub const BFFM_SETSTATUSTEXTW = 0x0468;
pub const CDM_SETCONTROLTEXT = 0x0468;
pub const EM_SETIMECOLOR = 0x0468;
pub const IPM_SETFOCUS = 0x0468;
pub const PSM_CHANGED = 0x0468;
pub const UDM_GETPOS = 0x0468;
pub const CDM_HIDECONTROL = 0x0469;
pub const EM_GETIMECOLOR = 0x0469;
pub const IPM_ISBLANK = 0x0469;
pub const PSM_RESTARTWINDOWS = 0x0469;
pub const UDM_SETBUDDY = 0x0469;
pub const CDM_SETDEFEXT = 0x046A;
pub const EM_SETIMEOPTIONS = 0x046A;
pub const PSM_REBOOTSYSTEM = 0x046A;
pub const UDM_GETBUDDY = 0x046A;
pub const EM_GETIMEOPTIONS = 0x046B;
pub const PSM_CANCELTOCLOSE = 0x046B;
pub const UDM_SETACCEL = 0x046B;
pub const EM_CONVPOSITION = 0x046C;
pub const PSM_QUERYSIBLINGS = 0x046C;
pub const UDM_GETACCEL = 0x046C;
pub const MCIWNDM_GETZOOM = 0x046D;
pub const PSM_UNCHANGED = 0x046D;
pub const UDM_SETBASE = 0x046D;
pub const PSM_APPLY = 0x046E;
pub const UDM_GETBASE = 0x046E;
pub const PSM_SETTITLEA = 0x046F;
pub const UDM_SETRANGE32 = 0x046F;
pub const PSM_SETWIZBUTTONS = 0x0470;
pub const UDM_GETRANGE32 = 0x0470;
pub const WM_CAP_DRIVER_GET_NAMEW = 0x0470;
pub const PSM_PRESSBUTTON = 0x0471;
pub const UDM_SETPOS32 = 0x0471;
pub const WM_CAP_DRIVER_GET_VERSIONW = 0x0471;
pub const PSM_SETCURSELID = 0x0472;
pub const UDM_GETPOS32 = 0x0472;
pub const PSM_SETFINISHTEXTA = 0x0473;
pub const PSM_GETTABCONTROL = 0x0474;
pub const PSM_ISDIALOGMESSAGE = 0x0475;
pub const MCIWNDM_REALIZE = 0x0476;
pub const PSM_GETCURRENTPAGEHWND = 0x0476;
pub const MCIWNDM_SETTIMEFORMATA = 0x0477;
pub const PSM_INSERTPAGE = 0x0477;
pub const EM_SETLANGOPTIONS = 0x0478;
pub const MCIWNDM_GETTIMEFORMATA = 0x0478;
pub const PSM_SETTITLEW = 0x0478;
pub const WM_CAP_FILE_SET_CAPTURE_FILEW = 0x0478;
pub const EM_GETLANGOPTIONS = 0x0479;
pub const MCIWNDM_VALIDATEMEDIA = 0x0479;
pub const PSM_SETFINISHTEXTW = 0x0479;
pub const WM_CAP_FILE_GET_CAPTURE_FILEW = 0x0479;
pub const EM_GETIMECOMPMODE = 0x047A;
pub const EM_FINDTEXTW = 0x047B;
pub const MCIWNDM_PLAYTO = 0x047B;
pub const WM_CAP_FILE_SAVEASW = 0x047B;
pub const EM_FINDTEXTEXW = 0x047C;
pub const MCIWNDM_GETFILENAMEA = 0x047C;
pub const EM_RECONVERSION = 0x047D;
pub const MCIWNDM_GETDEVICEA = 0x047D;
pub const PSM_SETHEADERTITLEA = 0x047D;
pub const WM_CAP_FILE_SAVEDIBW = 0x047D;
pub const EM_SETIMEMODEBIAS = 0x047E;
pub const MCIWNDM_GETPALETTE = 0x047E;
pub const PSM_SETHEADERTITLEW = 0x047E;
pub const EM_GETIMEMODEBIAS = 0x047F;
pub const MCIWNDM_SETPALETTE = 0x047F;
pub const PSM_SETHEADERSUBTITLEA = 0x047F;
pub const MCIWNDM_GETERRORA = 0x0480;
pub const PSM_SETHEADERSUBTITLEW = 0x0480;
pub const PSM_HWNDTOINDEX = 0x0481;
pub const PSM_INDEXTOHWND = 0x0482;
pub const MCIWNDM_SETINACTIVETIMER = 0x0483;
pub const PSM_PAGETOINDEX = 0x0483;
pub const PSM_INDEXTOPAGE = 0x0484;
pub const DL_BEGINDRAG = 0x0485;
pub const MCIWNDM_GETINACTIVETIMER = 0x0485;
pub const PSM_IDTOINDEX = 0x0485;
pub const DL_DRAGGING = 0x0486;
pub const PSM_INDEXTOID = 0x0486;
pub const DL_DROPPED = 0x0487;
pub const PSM_GETRESULT = 0x0487;
pub const DL_CANCELDRAG = 0x0488;
pub const PSM_RECALCPAGESIZES = 0x0488;
pub const MCIWNDM_GET_SOURCE = 0x048C;
pub const MCIWNDM_PUT_SOURCE = 0x048D;
pub const MCIWNDM_GET_DEST = 0x048E;
pub const MCIWNDM_PUT_DEST = 0x048F;
pub const MCIWNDM_CAN_PLAY = 0x0490;
pub const MCIWNDM_CAN_WINDOW = 0x0491;
pub const MCIWNDM_CAN_RECORD = 0x0492;
pub const MCIWNDM_CAN_SAVE = 0x0493;
pub const MCIWNDM_CAN_EJECT = 0x0494;
pub const MCIWNDM_CAN_CONFIG = 0x0495;
pub const IE_GETINK = 0x0496;
pub const MCIWNDM_PALETTEKICK = 0x0496;
pub const IE_SETINK = 0x0497;
pub const IE_GETPENTIP = 0x0498;
pub const IE_SETPENTIP = 0x0499;
pub const IE_GETERASERTIP = 0x049A;
pub const IE_SETERASERTIP = 0x049B;
pub const IE_GETBKGND = 0x049C;
pub const IE_SETBKGND = 0x049D;
pub const IE_GETGRIDORIGIN = 0x049E;
pub const IE_SETGRIDORIGIN = 0x049F;
pub const IE_GETGRIDPEN = 0x04A0;
pub const IE_SETGRIDPEN = 0x04A1;
pub const IE_GETGRIDSIZE = 0x04A2;
pub const IE_SETGRIDSIZE = 0x04A3;
pub const IE_GETMODE = 0x04A4;
pub const IE_SETMODE = 0x04A5;
pub const IE_GETINKRECT = 0x04A6;
pub const WM_CAP_SET_MCI_DEVICEW = 0x04A6;
pub const WM_CAP_GET_MCI_DEVICEW = 0x04A7;
pub const WM_CAP_PAL_OPENW = 0x04B4;
pub const WM_CAP_PAL_SAVEW = 0x04B5;
pub const IE_GETAPPDATA = 0x04B8;
pub const IE_SETAPPDATA = 0x04B9;
pub const IE_GETDRAWOPTS = 0x04BA;
pub const IE_SETDRAWOPTS = 0x04BB;
pub const IE_GETFORMAT = 0x04BC;
pub const IE_SETFORMAT = 0x04BD;
pub const IE_GETINKINPUT = 0x04BE;
pub const IE_SETINKINPUT = 0x04BF;
pub const IE_GETNOTIFY = 0x04C0;
pub const IE_SETNOTIFY = 0x04C1;
pub const IE_GETRECOG = 0x04C2;
pub const IE_SETRECOG = 0x04C3;
pub const IE_GETSECURITY = 0x04C4;
pub const IE_SETSECURITY = 0x04C5;
pub const IE_GETSEL = 0x04C6;
pub const IE_SETSEL = 0x04C7;
pub const EM_SETBIDIOPTIONS = 0x04C8;
pub const IE_DOCOMMAND = 0x04C8;
pub const MCIWNDM_NOTIFYMODE = 0x04C8;
pub const EM_GETBIDIOPTIONS = 0x04C9;
pub const IE_GETCOMMAND = 0x04C9;
pub const EM_SETTYPOGRAPHYOPTIONS = 0x04CA;
pub const IE_GETCOUNT = 0x04CA;
pub const EM_GETTYPOGRAPHYOPTIONS = 0x04CB;
pub const IE_GETGESTURE = 0x04CB;
pub const MCIWNDM_NOTIFYMEDIA = 0x04CB;
pub const EM_SETEDITSTYLE = 0x04CC;
pub const IE_GETMENU = 0x04CC;
pub const EM_GETEDITSTYLE = 0x04CD;
pub const IE_GETPAINTDC = 0x04CD;
pub const MCIWNDM_NOTIFYERROR = 0x04CD;
pub const IE_GETPDEVENT = 0x04CE;
pub const IE_GETSELCOUNT = 0x04CF;
pub const IE_GETSELITEMS = 0x04D0;
pub const IE_GETSTYLE = 0x04D1;
pub const MCIWNDM_SETTIMEFORMATW = 0x04DB;
pub const EM_OUTLINE = 0x04DC;
pub const MCIWNDM_GETTIMEFORMATW = 0x04DC;
pub const EM_GETSCROLLPOS = 0x04DD;
pub const EM_SETSCROLLPOS = 0x04DE;
pub const EM_SETFONTSIZE = 0x04DF;
pub const EM_GETZOOM = 0x04E0;
pub const MCIWNDM_GETFILENAMEW = 0x04E0;
pub const EM_SETZOOM = 0x04E1;
pub const MCIWNDM_GETDEVICEW = 0x04E1;
pub const EM_GETVIEWKIND = 0x04E2;
pub const EM_SETVIEWKIND = 0x04E3;
pub const EM_GETPAGE = 0x04E4;
pub const MCIWNDM_GETERRORW = 0x04E4;
pub const EM_SETPAGE = 0x04E5;
pub const EM_GETHYPHENATEINFO = 0x04E6;
pub const EM_SETHYPHENATEINFO = 0x04E7;
pub const EM_GETPAGEROTATE = 0x04EB;
pub const EM_SETPAGEROTATE = 0x04EC;
pub const EM_GETCTFMODEBIAS = 0x04ED;
pub const EM_SETCTFMODEBIAS = 0x04EE;
pub const EM_GETCTFOPENSTATUS = 0x04F0;
pub const EM_SETCTFOPENSTATUS = 0x04F1;
pub const EM_GETIMECOMPTEXT = 0x04F2;
pub const EM_ISIME = 0x04F3;
pub const EM_GETIMEPROPERTY = 0x04F4;
pub const EM_GETQUERYRTFOBJ = 0x050D;
pub const EM_SETQUERYRTFOBJ = 0x050E;
pub const FM_GETFOCUS = 0x0600;
pub const FM_GETDRIVEINFOA = 0x0601;
pub const FM_GETSELCOUNT = 0x0602;
pub const FM_GETSELCOUNTLFN = 0x0603;
pub const FM_GETFILESELA = 0x0604;
pub const FM_GETFILESELLFNA = 0x0605;
pub const FM_REFRESH_WINDOWS = 0x0606;
pub const FM_RELOAD_EXTENSIONS = 0x0607;
pub const FM_GETDRIVEINFOW = 0x0611;
pub const FM_GETFILESELW = 0x0614;
pub const FM_GETFILESELLFNW = 0x0615;
pub const WLX_WM_SAS = 0x0659;
pub const SM_GETSELCOUNT = 0x07E8;
pub const UM_GETSELCOUNT = 0x07E8;
pub const WM_CPL_LAUNCH = 0x07E8;
pub const SM_GETSERVERSELA = 0x07E9;
pub const UM_GETUSERSELA = 0x07E9;
pub const WM_CPL_LAUNCHED = 0x07E9;
pub const SM_GETSERVERSELW = 0x07EA;
pub const UM_GETUSERSELW = 0x07EA;
pub const SM_GETCURFOCUSA = 0x07EB;
pub const UM_GETGROUPSELA = 0x07EB;
pub const SM_GETCURFOCUSW = 0x07EC;
pub const UM_GETGROUPSELW = 0x07EC;
pub const SM_GETOPTIONS = 0x07ED;
pub const UM_GETCURFOCUSA = 0x07ED;
pub const UM_GETCURFOCUSW = 0x07EE;
pub const UM_GETOPTIONS = 0x07EF;
pub const UM_GETOPTIONS2 = 0x07F0;
pub const LVM_GETBKCOLOR = 0x1000;
pub const LVM_SETBKCOLOR = 0x1001;
pub const LVM_GETIMAGELIST = 0x1002;
pub const LVM_SETIMAGELIST = 0x1003;
pub const LVM_GETITEMCOUNT = 0x1004;
pub const LVM_GETITEMA = 0x1005;
pub const LVM_SETITEMA = 0x1006;
pub const LVM_INSERTITEMA = 0x1007;
pub const LVM_DELETEITEM = 0x1008;
pub const LVM_DELETEALLITEMS = 0x1009;
pub const LVM_GETCALLBACKMASK = 0x100A;
pub const LVM_SETCALLBACKMASK = 0x100B;
pub const LVM_GETNEXTITEM = 0x100C;
pub const LVM_FINDITEMA = 0x100D;
pub const LVM_GETITEMRECT = 0x100E;
pub const LVM_SETITEMPOSITION = 0x100F;
pub const LVM_GETITEMPOSITION = 0x1010;
pub const LVM_GETSTRINGWIDTHA = 0x1011;
pub const LVM_HITTEST = 0x1012;
pub const LVM_ENSUREVISIBLE = 0x1013;
pub const LVM_SCROLL = 0x1014;
pub const LVM_REDRAWITEMS = 0x1015;
pub const LVM_ARRANGE = 0x1016;
pub const LVM_EDITLABELA = 0x1017;
pub const LVM_GETEDITCONTROL = 0x1018;
pub const LVM_GETCOLUMNA = 0x1019;
pub const LVM_SETCOLUMNA = 0x101A;
pub const LVM_INSERTCOLUMNA = 0x101B;
pub const LVM_DELETECOLUMN = 0x101C;
pub const LVM_GETCOLUMNWIDTH = 0x101D;
pub const LVM_SETCOLUMNWIDTH = 0x101E;
pub const LVM_GETHEADER = 0x101F;
pub const LVM_CREATEDRAGIMAGE = 0x1021;
pub const LVM_GETVIEWRECT = 0x1022;
pub const LVM_GETTEXTCOLOR = 0x1023;
pub const LVM_SETTEXTCOLOR = 0x1024;
pub const LVM_GETTEXTBKCOLOR = 0x1025;
pub const LVM_SETTEXTBKCOLOR = 0x1026;
pub const LVM_GETTOPINDEX = 0x1027;
pub const LVM_GETCOUNTPERPAGE = 0x1028;
pub const LVM_GETORIGIN = 0x1029;
pub const LVM_UPDATE = 0x102A;
pub const LVM_SETITEMSTATE = 0x102B;
pub const LVM_GETITEMSTATE = 0x102C;
pub const LVM_GETITEMTEXTA = 0x102D;
pub const LVM_SETITEMTEXTA = 0x102E;
pub const LVM_SETITEMCOUNT = 0x102F;
pub const LVM_SORTITEMS = 0x1030;
pub const LVM_SETITEMPOSITION32 = 0x1031;
pub const LVM_GETSELECTEDCOUNT = 0x1032;
pub const LVM_GETITEMSPACING = 0x1033;
pub const LVM_GETISEARCHSTRINGA = 0x1034;
pub const LVM_SETICONSPACING = 0x1035;
pub const LVM_SETEXTENDEDLISTVIEWSTYLE = 0x1036;
pub const LVM_GETEXTENDEDLISTVIEWSTYLE = 0x1037;
pub const LVM_GETSUBITEMRECT = 0x1038;
pub const LVM_SUBITEMHITTEST = 0x1039;
pub const LVM_SETCOLUMNORDERARRAY = 0x103A;
pub const LVM_GETCOLUMNORDERARRAY = 0x103B;
pub const LVM_SETHOTITEM = 0x103C;
pub const LVM_GETHOTITEM = 0x103D;
pub const LVM_SETHOTCURSOR = 0x103E;
pub const LVM_GETHOTCURSOR = 0x103F;
pub const LVM_APPROXIMATEVIEWRECT = 0x1040;
pub const LVM_SETWORKAREAS = 0x1041;
pub const LVM_GETSELECTIONMARK = 0x1042;
pub const LVM_SETSELECTIONMARK = 0x1043;
pub const LVM_SETBKIMAGEA = 0x1044;
pub const LVM_GETBKIMAGEA = 0x1045;
pub const LVM_GETWORKAREAS = 0x1046;
pub const LVM_SETHOVERTIME = 0x1047;
pub const LVM_GETHOVERTIME = 0x1048;
pub const LVM_GETNUMBEROFWORKAREAS = 0x1049;
pub const LVM_SETTOOLTIPS = 0x104A;
pub const LVM_GETITEMW = 0x104B;
pub const LVM_SETITEMW = 0x104C;
pub const LVM_INSERTITEMW = 0x104D;
pub const LVM_GETTOOLTIPS = 0x104E;
pub const LVM_FINDITEMW = 0x1053;
pub const LVM_GETSTRINGWIDTHW = 0x1057;
pub const LVM_GETCOLUMNW = 0x105F;
pub const LVM_SETCOLUMNW = 0x1060;
pub const LVM_INSERTCOLUMNW = 0x1061;
pub const LVM_GETITEMTEXTW = 0x1073;
pub const LVM_SETITEMTEXTW = 0x1074;
pub const LVM_GETISEARCHSTRINGW = 0x1075;
pub const LVM_EDITLABELW = 0x1076;
pub const LVM_GETBKIMAGEW = 0x108B;
pub const LVM_SETSELECTEDCOLUMN = 0x108C;
pub const LVM_SETTILEWIDTH = 0x108D;
pub const LVM_SETVIEW = 0x108E;
pub const LVM_GETVIEW = 0x108F;
pub const LVM_INSERTGROUP = 0x1091;
pub const LVM_SETGROUPINFO = 0x1093;
pub const LVM_GETGROUPINFO = 0x1095;
pub const LVM_REMOVEGROUP = 0x1096;
pub const LVM_MOVEGROUP = 0x1097;
pub const LVM_MOVEITEMTOGROUP = 0x109A;
pub const LVM_SETGROUPMETRICS = 0x109B;
pub const LVM_GETGROUPMETRICS = 0x109C;
pub const LVM_ENABLEGROUPVIEW = 0x109D;
pub const LVM_SORTGROUPS = 0x109E;
pub const LVM_INSERTGROUPSORTED = 0x109F;
pub const LVM_REMOVEALLGROUPS = 0x10A0;
pub const LVM_HASGROUP = 0x10A1;
pub const LVM_SETTILEVIEWINFO = 0x10A2;
pub const LVM_GETTILEVIEWINFO = 0x10A3;
pub const LVM_SETTILEINFO = 0x10A4;
pub const LVM_GETTILEINFO = 0x10A5;
pub const LVM_SETINSERTMARK = 0x10A6;
pub const LVM_GETINSERTMARK = 0x10A7;
pub const LVM_INSERTMARKHITTEST = 0x10A8;
pub const LVM_GETINSERTMARKRECT = 0x10A9;
pub const LVM_SETINSERTMARKCOLOR = 0x10AA;
pub const LVM_GETINSERTMARKCOLOR = 0x10AB;
pub const LVM_SETINFOTIP = 0x10AD;
pub const LVM_GETSELECTEDCOLUMN = 0x10AE;
pub const LVM_ISGROUPVIEWENABLED = 0x10AF;
pub const LVM_GETOUTLINECOLOR = 0x10B0;
pub const LVM_SETOUTLINECOLOR = 0x10B1;
pub const LVM_CANCELEDITLABEL = 0x10B3;
pub const LVM_MAPINDEXTOID = 0x10B4;
pub const LVM_MAPIDTOINDEX = 0x10B5;
pub const LVM_ISITEMVISIBLE = 0x10B6;
pub const OCM__BASE = 0x2000;
pub const LVM_SETUNICODEFORMAT = 0x2005;
pub const LVM_GETUNICODEFORMAT = 0x2006;
pub const OCM_CTLCOLOR = 0x2019;
pub const OCM_DRAWITEM = 0x202B;
pub const OCM_MEASUREITEM = 0x202C;
pub const OCM_DELETEITEM = 0x202D;
pub const OCM_VKEYTOITEM = 0x202E;
pub const OCM_CHARTOITEM = 0x202F;
pub const OCM_COMPAREITEM = 0x2039;
pub const OCM_NOTIFY = 0x204E;
pub const OCM_COMMAND = 0x2111;
pub const OCM_HSCROLL = 0x2114;
pub const OCM_VSCROLL = 0x2115;
pub const OCM_CTLCOLORMSGBOX = 0x2132;
pub const OCM_CTLCOLOREDIT = 0x2133;
pub const OCM_CTLCOLORLISTBOX = 0x2134;
pub const OCM_CTLCOLORBTN = 0x2135;
pub const OCM_CTLCOLORDLG = 0x2136;
pub const OCM_CTLCOLORSCROLLBAR = 0x2137;
pub const OCM_CTLCOLORSTATIC = 0x2138;
pub const OCM_PARENTNOTIFY = 0x2210;
pub const WM_APP = 0x8000;
pub const WM_RASDIALEVENT = 0xCCCD;

pub extern "user32" fn GetMessageA(lpMsg: *MSG, hWnd: ?HWND, wMsgFilterMin: UINT, wMsgFilterMax: UINT) callconv(WINAPI) BOOL;
pub fn getMessageA(lpMsg: *MSG, hWnd: ?HWND, wMsgFilterMin: u32, wMsgFilterMax: u32) !void {
    const r = GetMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax);
    if (r == 0) return error.Quit;
    if (r != -1) return;
    switch (GetLastError()) {
        .INVALID_WINDOW_HANDLE => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn GetMessageW(lpMsg: *MSG, hWnd: ?HWND, wMsgFilterMin: UINT, wMsgFilterMax: UINT) callconv(WINAPI) BOOL;
pub var pfnGetMessageW: @TypeOf(GetMessageW) = undefined;
pub fn getMessageW(lpMsg: *MSG, hWnd: ?HWND, wMsgFilterMin: u32, wMsgFilterMax: u32) !void {
    const function = selectSymbol(GetMessageW, pfnGetMessageW, .win2k);

    const r = function(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax);
    if (r == 0) return error.Quit;
    if (r != -1) return;
    switch (GetLastError()) {
        .INVALID_WINDOW_HANDLE => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub const PM_NOREMOVE = 0x0000;
pub const PM_REMOVE = 0x0001;
pub const PM_NOYIELD = 0x0002;

pub extern "user32" fn PeekMessageA(lpMsg: *MSG, hWnd: ?HWND, wMsgFilterMin: UINT, wMsgFilterMax: UINT, wRemoveMsg: UINT) callconv(WINAPI) BOOL;
pub fn peekMessageA(lpMsg: *MSG, hWnd: ?HWND, wMsgFilterMin: u32, wMsgFilterMax: u32, wRemoveMsg: u32) !bool {
    const r = PeekMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
    if (r == 0) return false;
    if (r != -1) return true;
    switch (GetLastError()) {
        .INVALID_WINDOW_HANDLE => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn PeekMessageW(lpMsg: *MSG, hWnd: ?HWND, wMsgFilterMin: UINT, wMsgFilterMax: UINT, wRemoveMsg: UINT) callconv(WINAPI) BOOL;
pub var pfnPeekMessageW: @TypeOf(PeekMessageW) = undefined;
pub fn peekMessageW(lpMsg: *MSG, hWnd: ?HWND, wMsgFilterMin: u32, wMsgFilterMax: u32, wRemoveMsg: u32) !bool {
    const function = selectSymbol(PeekMessageW, pfnPeekMessageW, .win2k);

    const r = function(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
    if (r == 0) return false;
    if (r != -1) return true;
    switch (GetLastError()) {
        .INVALID_WINDOW_HANDLE => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn TranslateMessage(lpMsg: *const MSG) callconv(WINAPI) BOOL;
pub fn translateMessage(lpMsg: *const MSG) bool {
    return if (TranslateMessage(lpMsg) == 0) false else true;
}

pub extern "user32" fn DispatchMessageA(lpMsg: *const MSG) callconv(WINAPI) LRESULT;
pub fn dispatchMessageA(lpMsg: *const MSG) LRESULT {
    return DispatchMessageA(lpMsg);
}

pub extern "user32" fn DispatchMessageW(lpMsg: *const MSG) callconv(WINAPI) LRESULT;
pub var pfnDispatchMessageW: @TypeOf(DispatchMessageW) = undefined;
pub fn dispatchMessageW(lpMsg: *const MSG) LRESULT {
    const function = selectSymbol(DispatchMessageW, pfnDispatchMessageW, .win2k);
    return function(lpMsg);
}

pub extern "user32" fn PostQuitMessage(nExitCode: i32) callconv(WINAPI) void;
pub fn postQuitMessage(nExitCode: i32) void {
    PostQuitMessage(nExitCode);
}

pub extern "user32" fn DefWindowProcA(hWnd: HWND, Msg: UINT, wParam: WPARAM, lParam: LPARAM) callconv(WINAPI) LRESULT;
pub fn defWindowProcA(hWnd: HWND, Msg: UINT, wParam: WPARAM, lParam: LPARAM) LRESULT {
    return DefWindowProcA(hWnd, Msg, wParam, lParam);
}

pub extern "user32" fn DefWindowProcW(hWnd: HWND, Msg: UINT, wParam: WPARAM, lParam: LPARAM) callconv(WINAPI) LRESULT;
pub var pfnDefWindowProcW: @TypeOf(DefWindowProcW) = undefined;
pub fn defWindowProcW(hWnd: HWND, Msg: UINT, wParam: WPARAM, lParam: LPARAM) LRESULT {
    const function = selectSymbol(DefWindowProcW, pfnDefWindowProcW, .win2k);
    return function(hWnd, Msg, wParam, lParam);
}

// === Windows ===

pub const CS_VREDRAW = 0x0001;
pub const CS_HREDRAW = 0x0002;
pub const CS_DBLCLKS = 0x0008;
pub const CS_OWNDC = 0x0020;
pub const CS_CLASSDC = 0x0040;
pub const CS_PARENTDC = 0x0080;
pub const CS_NOCLOSE = 0x0200;
pub const CS_SAVEBITS = 0x0800;
pub const CS_BYTEALIGNCLIENT = 0x1000;
pub const CS_BYTEALIGNWINDOW = 0x2000;
pub const CS_GLOBALCLASS = 0x4000;

pub const WNDCLASSEXA = extern struct {
    cbSize: UINT = @sizeOf(WNDCLASSEXA),
    style: UINT,
    lpfnWndProc: WNDPROC,
    cbClsExtra: i32 = 0,
    cbWndExtra: i32 = 0,
    hInstance: HINSTANCE,
    hIcon: ?HICON,
    hCursor: ?HCURSOR,
    hbrBackground: ?HBRUSH,
    lpszMenuName: ?[*:0]const u8,
    lpszClassName: [*:0]const u8,
    hIconSm: ?HICON,
};

pub const WNDCLASSEXW = extern struct {
    cbSize: UINT = @sizeOf(WNDCLASSEXW),
    style: UINT,
    lpfnWndProc: WNDPROC,
    cbClsExtra: i32 = 0,
    cbWndExtra: i32 = 0,
    hInstance: HINSTANCE,
    hIcon: ?HICON,
    hCursor: ?HCURSOR,
    hbrBackground: ?HBRUSH,
    lpszMenuName: ?[*:0]const u16,
    lpszClassName: [*:0]const u16,
    hIconSm: ?HICON,
};

pub extern "user32" fn RegisterClassExA(*const WNDCLASSEXA) callconv(WINAPI) ATOM;
pub fn registerClassExA(window_class: *const WNDCLASSEXA) !ATOM {
    const atom = RegisterClassExA(window_class);
    if (atom != 0) return atom;
    switch (GetLastError()) {
        .CLASS_ALREADY_EXISTS => return error.AlreadyExists,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn RegisterClassExW(*const WNDCLASSEXW) callconv(WINAPI) ATOM;
pub var pfnRegisterClassExW: @TypeOf(RegisterClassExW) = undefined;
pub fn registerClassExW(window_class: *const WNDCLASSEXW) !ATOM {
    const function = selectSymbol(RegisterClassExW, pfnRegisterClassExW, .win2k);
    const atom = function(window_class);
    if (atom != 0) return atom;
    switch (GetLastError()) {
        .CLASS_ALREADY_EXISTS => return error.AlreadyExists,
        .CALL_NOT_IMPLEMENTED => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn UnregisterClassA(lpClassName: [*:0]const u8, hInstance: HINSTANCE) callconv(WINAPI) BOOL;
pub fn unregisterClassA(lpClassName: [*:0]const u8, hInstance: HINSTANCE) !void {
    if (UnregisterClassA(lpClassName, hInstance) == 0) {
        switch (GetLastError()) {
            .CLASS_DOES_NOT_EXIST => return error.ClassDoesNotExist,
            else => |err| return windows.unexpectedError(err),
        }
    }
}

pub extern "user32" fn UnregisterClassW(lpClassName: [*:0]const u16, hInstance: HINSTANCE) callconv(WINAPI) BOOL;
pub var pfnUnregisterClassW: @TypeOf(UnregisterClassW) = undefined;
pub fn unregisterClassW(lpClassName: [*:0]const u16, hInstance: HINSTANCE) !void {
    const function = selectSymbol(UnregisterClassW, pfnUnregisterClassW, .win2k);
    if (function(lpClassName, hInstance) == 0) {
        switch (GetLastError()) {
            .CLASS_DOES_NOT_EXIST => return error.ClassDoesNotExist,
            else => |err| return windows.unexpectedError(err),
        }
    }
}

pub const WS_OVERLAPPED = 0x00000000;
pub const WS_POPUP = 0x80000000;
pub const WS_CHILD = 0x40000000;
pub const WS_MINIMIZE = 0x20000000;
pub const WS_VISIBLE = 0x10000000;
pub const WS_DISABLED = 0x08000000;
pub const WS_CLIPSIBLINGS = 0x04000000;
pub const WS_CLIPCHILDREN = 0x02000000;
pub const WS_MAXIMIZE = 0x01000000;
pub const WS_CAPTION = WS_BORDER | WS_DLGFRAME;
pub const WS_BORDER = 0x00800000;
pub const WS_DLGFRAME = 0x00400000;
pub const WS_VSCROLL = 0x00200000;
pub const WS_HSCROLL = 0x00100000;
pub const WS_SYSMENU = 0x00080000;
pub const WS_THICKFRAME = 0x00040000;
pub const WS_GROUP = 0x00020000;
pub const WS_TABSTOP = 0x00010000;
pub const WS_MINIMIZEBOX = 0x00020000;
pub const WS_MAXIMIZEBOX = 0x00010000;
pub const WS_TILED = WS_OVERLAPPED;
pub const WS_ICONIC = WS_MINIMIZE;
pub const WS_SIZEBOX = WS_THICKFRAME;
pub const WS_TILEDWINDOW = WS_OVERLAPPEDWINDOW;
pub const WS_OVERLAPPEDWINDOW = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;
pub const WS_POPUPWINDOW = WS_POPUP | WS_BORDER | WS_SYSMENU;
pub const WS_CHILDWINDOW = WS_CHILD;

pub const WS_EX_DLGMODALFRAME = 0x00000001;
pub const WS_EX_NOPARENTNOTIFY = 0x00000004;
pub const WS_EX_TOPMOST = 0x00000008;
pub const WS_EX_ACCEPTFILES = 0x00000010;
pub const WS_EX_TRANSPARENT = 0x00000020;
pub const WS_EX_MDICHILD = 0x00000040;
pub const WS_EX_TOOLWINDOW = 0x00000080;
pub const WS_EX_WINDOWEDGE = 0x00000100;
pub const WS_EX_CLIENTEDGE = 0x00000200;
pub const WS_EX_CONTEXTHELP = 0x00000400;
pub const WS_EX_RIGHT = 0x00001000;
pub const WS_EX_LEFT = 0x00000000;
pub const WS_EX_RTLREADING = 0x00002000;
pub const WS_EX_LTRREADING = 0x00000000;
pub const WS_EX_LEFTSCROLLBAR = 0x00004000;
pub const WS_EX_RIGHTSCROLLBAR = 0x00000000;
pub const WS_EX_CONTROLPARENT = 0x00010000;
pub const WS_EX_STATICEDGE = 0x00020000;
pub const WS_EX_APPWINDOW = 0x00040000;
pub const WS_EX_LAYERED = 0x00080000;
pub const WS_EX_OVERLAPPEDWINDOW = WS_EX_WINDOWEDGE | WS_EX_CLIENTEDGE;
pub const WS_EX_PALETTEWINDOW = WS_EX_WINDOWEDGE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST;

pub const CW_USEDEFAULT = @bitCast(i32, @as(u32, 0x80000000));

pub extern "user32" fn CreateWindowExA(dwExStyle: DWORD, lpClassName: [*:0]const u8, lpWindowName: [*:0]const u8, dwStyle: DWORD, X: i32, Y: i32, nWidth: i32, nHeight: i32, hWindParent: ?HWND, hMenu: ?HMENU, hInstance: HINSTANCE, lpParam: ?LPVOID) callconv(WINAPI) ?HWND;
pub fn createWindowExA(dwExStyle: u32, lpClassName: [*:0]const u8, lpWindowName: [*:0]const u8, dwStyle: u32, X: i32, Y: i32, nWidth: i32, nHeight: i32, hWindParent: ?HWND, hMenu: ?HMENU, hInstance: HINSTANCE, lpParam: ?*c_void) !HWND {
    const window = CreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWindParent, hMenu, hInstance, lpParam);
    if (window) |win| return win;

    switch (GetLastError()) {
        .CLASS_DOES_NOT_EXIST => return error.ClassDoesNotExist,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn CreateWindowExW(dwExStyle: DWORD, lpClassName: [*:0]const u16, lpWindowName: [*:0]const u16, dwStyle: DWORD, X: i32, Y: i32, nWidth: i32, nHeight: i32, hWindParent: ?HWND, hMenu: ?HMENU, hInstance: HINSTANCE, lpParam: ?LPVOID) callconv(WINAPI) ?HWND;
pub var pfnCreateWindowExW: @TypeOf(CreateWindowExW) = undefined;
pub fn createWindowExW(dwExStyle: u32, lpClassName: [*:0]const u16, lpWindowName: [*:0]const u16, dwStyle: u32, X: i32, Y: i32, nWidth: i32, nHeight: i32, hWindParent: ?HWND, hMenu: ?HMENU, hInstance: HINSTANCE, lpParam: ?*c_void) !HWND {
    const function = selectSymbol(CreateWindowExW, pfnCreateWindowExW, .win2k);
    const window = function(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWindParent, hMenu, hInstance, lpParam);
    if (window) |win| return win;

    switch (GetLastError()) {
        .CLASS_DOES_NOT_EXIST => return error.ClassDoesNotExist,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn DestroyWindow(hWnd: HWND) callconv(WINAPI) BOOL;
pub fn destroyWindow(hWnd: HWND) !void {
    if (DestroyWindow(hWnd) == 0) {
        switch (GetLastError()) {
            .INVALID_WINDOW_HANDLE => unreachable,
            .INVALID_PARAMETER => unreachable,
            else => |err| return windows.unexpectedError(err),
        }
    }
}

pub const SW_HIDE = 0;
pub const SW_SHOWNORMAL = 1;
pub const SW_NORMAL = 1;
pub const SW_SHOWMINIMIZED = 2;
pub const SW_SHOWMAXIMIZED = 3;
pub const SW_MAXIMIZE = 3;
pub const SW_SHOWNOACTIVATE = 4;
pub const SW_SHOW = 5;
pub const SW_MINIMIZE = 6;
pub const SW_SHOWMINNOACTIVE = 7;
pub const SW_SHOWNA = 8;
pub const SW_RESTORE = 9;
pub const SW_SHOWDEFAULT = 10;
pub const SW_FORCEMINIMIZE = 11;
pub const SW_MAX = 11;

pub extern "user32" fn ShowWindow(hWnd: HWND, nCmdShow: i32) callconv(WINAPI) BOOL;
pub fn showWindow(hWnd: HWND, nCmdShow: i32) bool {
    return (ShowWindow(hWnd, nCmdShow) == TRUE);
}

pub extern "user32" fn UpdateWindow(hWnd: HWND) callconv(WINAPI) BOOL;
pub fn updateWindow(hWnd: HWND) !void {
    if (ShowWindow(hWnd, nCmdShow) == 0) {
        switch (GetLastError()) {
            .INVALID_WINDOW_HANDLE => unreachable,
            .INVALID_PARAMETER => unreachable,
            else => |err| return windows.unexpectedError(err),
        }
    }
}

pub extern "user32" fn AdjustWindowRectEx(lpRect: *RECT, dwStyle: DWORD, bMenu: BOOL, dwExStyle: DWORD) callconv(WINAPI) BOOL;
pub fn adjustWindowRectEx(lpRect: *RECT, dwStyle: u32, bMenu: bool, dwExStyle: u32) !void {
    assert(dwStyle & WS_OVERLAPPED == 0);

    if (AdjustWindowRectEx(lpRect, dwStyle, bMenu, dwExStyle) == 0) {
        switch (GetLastError()) {
            .INVALID_PARAMETER => unreachable,
            else => |err| return windows.unexpectedError(err),
        }
    }
}

pub const GWL_WNDPROC = -4;
pub const GWL_HINSTANCE = -6;
pub const GWL_HWNDPARENT = -8;
pub const GWL_STYLE = -16;
pub const GWL_EXSTYLE = -20;
pub const GWL_USERDATA = -21;
pub const GWL_ID = -12;

pub extern "user32" fn GetWindowLongA(hWnd: HWND, nIndex: i32) callconv(WINAPI) LONG;
pub fn getWindowLongA(hWnd: HWND, nIndex: i32) !i32 {
    const value = GetWindowLongA(hWnd, nIndex);
    if (value != 0) return value;

    switch (GetLastError()) {
        .SUCCESS => return 0,
        .INVALID_WINDOW_HANDLE => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn GetWindowLongW(hWnd: HWND, nIndex: i32) callconv(WINAPI) LONG;
pub var pfnGetWindowLongW: @TypeOf(GetWindowLongW) = undefined;
pub fn getWindowLongW(hWnd: HWND, nIndex: i32) !i32 {
    const function = selectSymbol(GetWindowLongW, pfnGetWindowLongW, .win2k);

    const value = function(hWnd, nIndex);
    if (value != 0) return value;

    switch (GetLastError()) {
        .SUCCESS => return 0,
        .INVALID_WINDOW_HANDLE => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn GetWindowLongPtrA(hWnd: HWND, nIndex: i32) callconv(WINAPI) LONG_PTR;
pub fn getWindowLongPtrA(hWnd: HWND, nIndex: i32) !isize {
    // "When compiling for 32-bit Windows, GetWindowLongPtr is defined as a call to the GetWindowLong function."
    // https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowlongptrw
    if (@sizeOf(LONG_PTR) == 4) return getWindowLongA(hWnd, nIndex);

    const value = GetWindowLongPtrA(hWnd, nIndex);
    if (value != 0) return value;

    switch (GetLastError()) {
        .SUCCESS => return 0,
        .INVALID_WINDOW_HANDLE => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn GetWindowLongPtrW(hWnd: HWND, nIndex: i32) callconv(WINAPI) LONG_PTR;
pub var pfnGetWindowLongPtrW: @TypeOf(GetWindowLongPtrW) = undefined;
pub fn getWindowLongPtrW(hWnd: HWND, nIndex: i32) !isize {
    if (@sizeOf(LONG_PTR) == 4) return getWindowLongW(hWnd, nIndex);
    const function = selectSymbol(GetWindowLongPtrW, pfnGetWindowLongPtrW, .win2k);

    const value = function(hWnd, nIndex);
    if (value != 0) return value;

    switch (GetLastError()) {
        .SUCCESS => return 0,
        .INVALID_WINDOW_HANDLE => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn SetWindowLongA(hWnd: HWND, nIndex: i32, dwNewLong: LONG) callconv(WINAPI) LONG;
pub fn setWindowLongA(hWnd: HWND, nIndex: i32, dwNewLong: i32) !i32 {
    // [...] you should clear the last error information by calling SetLastError with 0 before calling SetWindowLong.
    // https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowlonga
    SetLastError(.SUCCESS);

    const value = SetWindowLongA(hWnd, nIndex, dwNewLong);
    if (value != 0) return value;

    switch (GetLastError()) {
        .SUCCESS => return 0,
        .INVALID_WINDOW_HANDLE => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn SetWindowLongW(hWnd: HWND, nIndex: i32, dwNewLong: LONG) callconv(WINAPI) LONG;
pub var pfnSetWindowLongW: @TypeOf(SetWindowLongW) = undefined;
pub fn setWindowLongW(hWnd: HWND, nIndex: i32, dwNewLong: i32) !i32 {
    const function = selectSymbol(SetWindowLongW, pfnSetWindowLongW, .win2k);

    SetLastError(.SUCCESS);
    const value = function(hWnd, nIndex, dwNewLong);
    if (value != 0) return value;

    switch (GetLastError()) {
        .SUCCESS => return 0,
        .INVALID_WINDOW_HANDLE => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn SetWindowLongPtrA(hWnd: HWND, nIndex: i32, dwNewLong: LONG_PTR) callconv(WINAPI) LONG_PTR;
pub fn setWindowLongPtrA(hWnd: HWND, nIndex: i32, dwNewLong: isize) !isize {
    // "When compiling for 32-bit Windows, GetWindowLongPtr is defined as a call to the GetWindowLong function."
    // https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowlongptrw
    if (@sizeOf(LONG_PTR) == 4) return setWindowLongA(hWnd, nIndex, dwNewLong);

    SetLastError(.SUCCESS);
    const value = SetWindowLongPtrA(hWnd, nIndex, dwNewLong);
    if (value != 0) return value;

    switch (GetLastError()) {
        .SUCCESS => return 0,
        .INVALID_WINDOW_HANDLE => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn SetWindowLongPtrW(hWnd: HWND, nIndex: i32, dwNewLong: LONG_PTR) callconv(WINAPI) LONG_PTR;
pub var pfnSetWindowLongPtrW: @TypeOf(SetWindowLongPtrW) = undefined;
pub fn setWindowLongPtrW(hWnd: HWND, nIndex: i32, dwNewLong: isize) !isize {
    if (@sizeOf(LONG_PTR) == 4) return setWindowLongW(hWnd, nIndex, dwNewLong);
    const function = selectSymbol(SetWindowLongPtrW, pfnSetWindowLongPtrW, .win2k);

    SetLastError(.SUCCESS);
    const value = function(hWnd, nIndex, dwNewLong);
    if (value != 0) return value;

    switch (GetLastError()) {
        .SUCCESS => return 0,
        .INVALID_WINDOW_HANDLE => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn GetDC(hWnd: ?HWND) callconv(WINAPI) ?HDC;
pub fn getDC(hWnd: ?HWND) !HDC {
    const hdc = GetDC(hWnd);
    if (hdc) |h| return h;

    switch (GetLastError()) {
        .INVALID_WINDOW_HANDLE => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn ReleaseDC(hWnd: ?HWND, hDC: HDC) callconv(WINAPI) i32;
pub fn releaseDC(hWnd: ?HWND, hDC: HDC) bool {
    return if (ReleaseDC(hWnd, hDC) == 1) true else false;
}

// === Modal dialogue boxes ===

pub const MB_OK = 0x00000000;
pub const MB_OKCANCEL = 0x00000001;
pub const MB_ABORTRETRYIGNORE = 0x00000002;
pub const MB_YESNOCANCEL = 0x00000003;
pub const MB_YESNO = 0x00000004;
pub const MB_RETRYCANCEL = 0x00000005;
pub const MB_CANCELTRYCONTINUE = 0x00000006;
pub const MB_ICONHAND = 0x00000010;
pub const MB_ICONQUESTION = 0x00000020;
pub const MB_ICONEXCLAMATION = 0x00000030;
pub const MB_ICONASTERISK = 0x00000040;
pub const MB_USERICON = 0x00000080;
pub const MB_ICONWARNING = MB_ICONEXCLAMATION;
pub const MB_ICONERROR = MB_ICONHAND;
pub const MB_ICONINFORMATION = MB_ICONASTERISK;
pub const MB_ICONSTOP = MB_ICONHAND;
pub const MB_DEFBUTTON1 = 0x00000000;
pub const MB_DEFBUTTON2 = 0x00000100;
pub const MB_DEFBUTTON3 = 0x00000200;
pub const MB_DEFBUTTON4 = 0x00000300;
pub const MB_APPLMODAL = 0x00000000;
pub const MB_SYSTEMMODAL = 0x00001000;
pub const MB_TASKMODAL = 0x00002000;
pub const MB_HELP = 0x00004000;
pub const MB_NOFOCUS = 0x00008000;
pub const MB_SETFOREGROUND = 0x00010000;
pub const MB_DEFAULT_DESKTOP_ONLY = 0x00020000;
pub const MB_TOPMOST = 0x00040000;
pub const MB_RIGHT = 0x00080000;
pub const MB_RTLREADING = 0x00100000;
pub const MB_TYPEMASK = 0x0000000F;
pub const MB_ICONMASK = 0x000000F0;
pub const MB_DEFMASK = 0x00000F00;
pub const MB_MODEMASK = 0x00003000;
pub const MB_MISCMASK = 0x0000C000;

pub const IDOK = 1;
pub const IDCANCEL = 2;
pub const IDABORT = 3;
pub const IDRETRY = 4;
pub const IDIGNORE = 5;
pub const IDYES = 6;
pub const IDNO = 7;
pub const IDCLOSE = 8;
pub const IDHELP = 9;
pub const IDTRYAGAIN = 10;
pub const IDCONTINUE = 11;

pub extern "user32" fn MessageBoxA(hWnd: ?HWND, lpText: [*:0]const u8, lpCaption: [*:0]const u8, uType: UINT) callconv(WINAPI) i32;
pub fn messageBoxA(hWnd: ?HWND, lpText: [*:0]const u8, lpCaption: [*:0]const u8, uType: u32) !i32 {
    const value = MessageBoxA(hWnd, lpText, lpCaption, uType);
    if (value != 0) return value;
    switch (GetLastError()) {
        .INVALID_WINDOW_HANDLE => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}

pub extern "user32" fn MessageBoxW(hWnd: ?HWND, lpText: [*:0]const u16, lpCaption: ?[*:0]const u16, uType: UINT) callconv(WINAPI) i32;
pub var pfnMessageBoxW: @TypeOf(MessageBoxW) = undefined;
pub fn messageBoxW(hWnd: ?HWND, lpText: [*:0]const u16, lpCaption: [*:0]const u16, uType: u32) !i32 {
    const function = selectSymbol(MessageBoxW, pfnMessageBoxW, .win2k);
    const value = function(hWnd, lpText, lpCaption, uType);
    if (value != 0) return value;
    switch (GetLastError()) {
        .INVALID_WINDOW_HANDLE => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => |err| return windows.unexpectedError(err),
    }
}
