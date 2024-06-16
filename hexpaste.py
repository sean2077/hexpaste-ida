############################################################################################
##
## One-Click Hex Paste!
##
## Available for IDA 7+ and Python 3.8+
##
## To install:
##      Copy script into plugins directory, i.e: C:\Program Files\<ida version>\plugins
##
## To run:
##      Right-click on an address in the disassembly and select "Hex Paste"
##      The hex encoded bytes from the clipboard will be written to the selected address
##
############################################################################################

__AUTHOR__ = "@sean2077"

PLUGIN_NAME = "Hex Paste"
PLUGIN_HOTKEY = "Ctrl+Shift+V"
VERSION = "1.0.0"

ACTION_PREFIX = "sean2077"

import re

import idaapi
import idc

major, minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = major > 6

if using_ida7api:
    import PyQt5.QtCore as QtCore
    import PyQt5.QtGui as QtGui
    import PyQt5.QtWidgets as QtWidgets
    from PyQt5.Qt import QApplication
else:
    import PySide.QtCore as QtCore
    import PySide.QtGui as QtGui

    QtWidgets = QtGui
    QtCore.pyqtSignal = QtCore.Signal
    QtCore.pyqtSlot = QtCore.Slot
    from PySide.QtGui import QApplication


def get_clipboard_data():
    return QApplication.clipboard().text()


def validate_hex_string(hex_string):
    # Remove all whitespace and convert to uppercase
    cleaned = re.sub(r"\s+", "", hex_string).upper()
    # Check if it's a valid hex string
    if re.fullmatch(r"[0-9A-F]*", cleaned):
        return cleaned
    return None


def write_bytes_to_address(address, hex_string):
    bytes_data = bytes.fromhex(hex_string)
    idaapi.patch_bytes(address, bytes_data)


def show_message(title, message):
    msg_box = QtWidgets.QMessageBox()
    msg_box.setIcon(QtWidgets.QMessageBox.Information)
    msg_box.setWindowTitle(title)
    msg_box.setText(message)
    msg_box.setStandardButtons(QtWidgets.QMessageBox.Ok)
    msg_box.exec_()


def confirm_write(hex_string, address):
    msg_box = QtWidgets.QMessageBox()
    msg_box.setIcon(QtWidgets.QMessageBox.Question)
    msg_box.setWindowTitle("Confirm Hex Paste")
    msg_box.setText(f"Are you sure you want to write the following bytes to address {address:X}?\n\n{hex_string}")
    msg_box.setStandardButtons(QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
    return msg_box.exec_() == QtWidgets.QMessageBox.Yes


def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return hex_paste()


class hex_paste(idaapi.plugin_t):
    """
    The IDA Plugin for hex paste.
    """

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Paste Hex Bytes"
    help = "Right-click an address and select 'Paste Hex'"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """
        self._init_action_paste_bytes()
        self._init_hooks()
        idaapi.msg("%s %s initialized...\n" % (self.wanted_name, VERSION))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        idaapi.msg("%s cannot be run as a script.\n" % self.wanted_name)

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """
        self._hooks.unhook()
        self._del_action_paste_bytes()
        idaapi.msg("%s terminated...\n" % self.wanted_name)

    def _init_hooks(self):
        """
        Install plugin hooks into IDA.
        """
        self._hooks = Hooks()
        self._hooks.hook()

    ACTION_PASTE_BYTES = f"{ACTION_PREFIX}:paste_bytes"

    def _init_action_paste_bytes(self):
        """
        Register the paste bytes action with IDA.
        """
        action_desc = idaapi.action_desc_t(
            self.ACTION_PASTE_BYTES,  # The action name.
            "Paste Hex",  # The action text.
            IDACtxEntry(paste_bytes),  # The action handler.
            PLUGIN_HOTKEY,  # Optional: action shortcut
            "Paste hex bytes from clipboard",  # Optional: tooltip
            31,  # Icon
        )
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_paste_bytes(self):
        """
        Delete the paste action from IDA.
        """
        idaapi.unregister_action(self.ACTION_PASTE_BYTES)


class Hooks(idaapi.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup):
        """
        A right-click menu is about to be shown. (IDA 7)
        """
        inject_hex_paste_actions(widget, popup, idaapi.get_widget_type(widget))
        return 0

    def finish_populating_tform_popup(self, form, popup):
        """
        A right-click menu is about to be shown. (IDA 6.x)
        """
        inject_hex_paste_actions(form, popup, idaapi.get_tform_type(form))
        return 0


def inject_hex_paste_actions(form, popup, form_type):
    """
    Inject paste actions to popup menu(s) based on context.
    """
    if form_type == idaapi.BWN_DISASMS:
        idaapi.attach_action_to_popup(form, popup, hex_paste.ACTION_PASTE_BYTES, "Paste Hex", idaapi.SETMENU_APP)
    return 0


def paste_bytes():
    """
    Paste bytes from clipboard to selected address
    """
    ea = idc.get_screen_ea()
    if ea == idaapi.BADADDR:
        idaapi.msg("Invalid address selected\n")
        return

    clipboard_data = get_clipboard_data()
    valid_hex = validate_hex_string(clipboard_data)
    if not valid_hex:
        show_message("Invalid Hex String", f"Invalid hex string in clipboard: {clipboard_data}\n")
        idaapi.msg("Invalid hex string in clipboard\n")
        return

    if confirm_write(valid_hex, ea):
        write_bytes_to_address(ea, valid_hex)
        idaapi.msg("Hex bytes pasted to address %x\n" % ea)
    else:
        idaapi.msg("Hex paste cancelled\n")


class IDACtxEntry(idaapi.action_handler_t):
    """
    A basic Context Menu class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        self.action_function()
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return idaapi.AST_ENABLE_ALWAYS
