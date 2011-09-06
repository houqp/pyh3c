#!/usr/bin/env python

import pygtk
pygtk.require('2.0')
import gtk
import glib

import pcap
import dpkt
import binascii
import dnet
import subprocess
import threading
from os import getuid

from pyh3c import *
from h3cRadius import *
from h3cPack import *
import h3cStatus

def create_Table(rows=1, columns=1, homogeneous=False):
  table = gtk.Table(rows, columns, homogeneous)
  table.set_row_spacings(10)
  table.show()
  return table

def create_Frame(label=None):
  frame = gtk.Frame(label)
  frame.set_label_align(0, 0)
  frame.show()
  return frame

def create_MenuItem(name, callback=None, data=None):
  item = gtk.MenuItem(name)
  if callback:
    item.connect("activate", callback, data)
  item.show()
  return item

def create_OptionMenu(menu):
  opt = gtk.OptionMenu()
  opt.set_menu(menu)
  opt.show()
  return opt

def create_MenuBar():
  menu_bar = gtk.MenuBar()
  menu_bar.show()
  return menu_bar

def create_Label(str):
  label = gtk.Label(str)
  #label.set_justify(gtk.JUSTIFY_LEFT)
  label.show()
  return label

def create_Button(lable=None, stock=None):
  button = gtk.Button(lable, stock)
  button.show()
  return button

def create_VBox(homogeneous, spacing):
  vbox = gtk.VBox(homogeneous, spacing)
  vbox.show()
  return vbox
 
def create_HBox(homogeneous, spacing):
  hbox = gtk.HBox(homogeneous, spacing)
  hbox.show()
  return hbox

def create_TextView(buffer=None):
  tv = gtk.TextView()
  if buffer:
    gtkTextBuffer = tv.get_buffer()
    gtkTextBuffer.set_text(buffer)
  tv.set_editable(False)
  tv.set_left_margin(10)
  tv.set_right_margin(10)
  tv.set_cursor_visible(False) 
  tv.show()
  return tv

def create_ScrolledWindow():
  sw = gtk.ScrolledWindow()
  sw.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
  sw.set_border_width(10)
  sw.show()
  return sw

def create_Entry(max=0, text=None):
  entry = gtk.Entry(max)
  if text:
    entry.set_text(text)
  entry.show()
  return entry

def show_dialog(title, str):
  dialog = gtk.Dialog(title)
  label = create_Label(str)
  dialog.set_border_width(20)
  dialog.vbox.pack_start(label, True, True, 10)
  button_ok = create_Button("OK", gtk.STOCK_OK)
  button_ok.connect_object("clicked", gtk.Widget.destroy, dialog)
  dialog.vbox.pack_start(button_ok, False, False, 10)
  dialog.show()

#--- [callback function] ---

class H3C_GUI:
  def __init__(self):

    self.pyh3c = PyH3C()

    self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
    self.window.show()

    #register signals with handlers
    self.window.connect("delete_event", self.delete_event)
    self.window.connect("destroy", self.destroy) 
    #self.window.set_border_width(20)

    #setup boxes
    box_root = create_VBox(False, 0)

    box_main = create_VBox(False, 0)
    box_main.set_border_width(10)

    box_config = create_VBox(False, 0)
    box_buttons = create_HBox(False, 0)
    #endof boxes

    #setup table
    table_config = create_Table(3, 2, True)
    #endof table

    #setup labels
    label_user = create_Label("User name:")
    label_pass = create_Label("Passward:")
    label_eth = create_Label("Interfaces:")
    label_dhcp = create_Label("DHCP scripts:")
    label_ping_target = create_Label("Ping target:")
    #endof labels

    #setup entry
    self.entry_user = create_Entry(0, None)
    self.entry_user.connect("changed", self.user_name_changed)
    self.entry_pass = create_Entry(0, None)
    self.entry_pass.set_visibility(gtk.FALSE)
    self.entry_pass.connect("changed", self.user_pass_changed)
    self.entry_dhcp = create_Entry(0, None)
    self.entry_dhcp.connect("changed", self.dhcp_command_changed)
    self.entry_ping_target = create_Entry(0, None)
    self.entry_ping_target.connect("changed", self.ping_target_changed)
    #endof entry

    #setup root_menu
    root_menu_bar = create_MenuBar()

    file_menu = gtk.Menu()
    file_item = create_MenuItem("File")
    quit_item = create_MenuItem("Quit", self.destroy)

    help_menu = gtk.Menu()
    help_item = create_MenuItem("Help")
    about_item = create_MenuItem("About", self.hello)
    #endof root_menu
  
    #setup OptionMenus
    menu_dev = gtk.Menu()
    for dev in self.pyh3c.get_devices():
      if dev != "lo":
        item = create_MenuItem(dev, self.change_dev, dev)
        menu_dev.append(item)
    opt_dev = create_OptionMenu(menu_dev)
    #endof OptionMenus

    #setup buttons
    button_save_config = create_Button("Save")
    button_save_config.connect("clicked", self.save_config, None)

    button_connect = create_Button("Connect")
    button_connect.connect("clicked", self.pressed_connect, None)

    button_disconnect = create_Button("Disconnect")
    button_disconnect.connect("clicked", self.pressed_disconnect, None)

    button_hide = create_Button("Hide me!")
    button_hide.connect("clicked", self.pressed_hide, None)

    button_quit = create_Button("Quit", gtk.STOCK_QUIT)
    button_quit.connect("clicked", lambda a,b: gtk.main_quit(), None)
    #endup buttons

    #setup frames
    frame_config = create_Frame("Configuration:")
    frame_status = create_Frame("Connection status:")
    #endof frames

    #setup TextView
    welcome_text = """
"""
    textview_status = create_TextView(welcome_text)
    textview_sw_status = create_ScrolledWindow()
    textview_sw_status.add(textview_status)
    self.buffer_status = textview_status.get_buffer()
    #endof TextView

    #setup separators
    hsep_status = gtk.HSeparator() 
    hsep_status.show()
    #endup separators


    #start to pack widgets
    self.window.add(box_root)
    #-----------------------------
    box_root.pack_start(root_menu_bar, False, False, 0)
    box_root.pack_start(box_main, False, False, 0)
    #-----------------------------
    box_main.pack_start(frame_config, False, False, 10)
    box_main.pack_start(frame_status, True, True, 10)
    box_main.pack_start(hsep_status, False, False, 10)
    box_main.pack_start(box_buttons, False, False, 10)
    #-----------------------------
    # start of menu bar
    root_menu_bar.append(file_item)
    file_item.set_submenu(file_menu)
    root_menu_bar.append(help_item)
    help_item.set_submenu(help_menu)

    file_menu.append(quit_item)
    help_menu.append(about_item)

    # start of table
    frame_config.add(box_config)
    box_config.pack_start(table_config, False, False, 10)
    #   0       1       2
    # 0 +-------+-------+
    #   | user  |       |
    # 1 +-------+-------+
    #   | pass  |       |
    # 2 +-------+-------+
    #   | eth   |       |
    # 3 +-------+-------+
    #   | dhcp  |       |
    # 4 +-------+-------+
    table_config.attach(label_user, 0, 1, 0, 1, gtk.FILL, gtk.FILL, 0, 0)
    table_config.attach(self.entry_user, 1, 2, 0, 1, gtk.FILL, gtk.FILL, 0, 0)

    table_config.attach(label_pass, 0, 1, 1, 2, gtk.FILL, gtk.FILL, 0, 0)
    table_config.attach(self.entry_pass, 1, 2, 1, 2, gtk.FILL, gtk.FILL, 0, 0)

    table_config.attach(label_eth, 0, 1, 2, 3, gtk.FILL, gtk.FILL, 0, 0)
    table_config.attach(opt_dev, 1, 2, 2, 3, gtk.FILL, gtk.FILL, 0, 0)

    table_config.attach(label_dhcp, 0, 1, 3, 4, gtk.FILL, gtk.FILL, 0, 0)
    table_config.attach(self.entry_dhcp, 1, 2, 3, 4, gtk.FILL, gtk.FILL, 0, 0)

    table_config.attach(label_ping_target, 0, 1, 4, 5, gtk.FILL, gtk.FILL, 0, 0)
    table_config.attach(self.entry_ping_target, 1, 2, 4, 5, gtk.FILL, gtk.FILL, 0, 0)
    
    box_config.pack_start(button_save_config, True, False, 5)
    #box_config.pack_start(entry_user, False, False, 0)

    # start of status info
    frame_status.add(textview_sw_status)

    # start of buttons
    box_buttons.pack_start(button_connect, False, False, 5)
    box_buttons.pack_start(button_disconnect, False, False, 5)
    box_buttons.pack_start(button_hide, False, False, 5)
    box_buttons.pack_end(button_quit, False, False, 5)
    #endof packing

    #do some real initialization here

    #check whether the file exits before loading
    try:
      fp = open('pyh3c.conf')
    except IOError:
      pass
    else:
      self.pyh3c.h3cStatus.load_config()

    self.entry_user.set_text(self.pyh3c.h3cStatus.user_name)
    self.entry_pass.set_text(self.pyh3c.h3cStatus.user_pass)
    self.entry_dhcp.set_text(self.pyh3c.h3cStatus.dhcp_command)
    self.entry_ping_target.set_text(self.pyh3c.h3cStatus.ping_target)

    try:
      opt_dev.set_history(
        self.pyh3c.get_devices().index(self.pyh3c.h3cStatus.dev) - 1
        )
    except ValueError:
      pass

    #self.pyh3c_instance = subprocess.Popen(
        #["python", "-u", "pyh3c.py", "-k"], 
        #stdout = subprocess.PIPE        
        #)
    self.pyh3c_instance = subprocess.Popen(
        ["python", "-u", "test.py"], 
        stdout = subprocess.PIPE        
        )
    self.status_output = self.STATUS_OUTPUT(self)

    #passer = threading.Thread(group=None, target=self.pyh3c_output_passer, name='passer', args=(self.status_output,), kwargs={})
    #passer.daemon = True
    #passer.start()

    glib.timeout_add_seconds(1, self.pyh3c_output_passer, )

    #self.pyh3c_output_passer()

  def hello(self, widget, data=None):
    about_messg = """
PyH3C is a freesoftware! You can download 
the source code at:
https://github.com/houqp/pyh3c
Happy hacking :-)

Author: houqp
"""
    show_dialog("About", about_messg)

  def pressed_connect(self, widget, data=None):
    return

  def pressed_disconnect(self, widget, data=None):
    pass

  def pressed_hide(self, widget, data=None):
    self.window.iconify()
    pass

  def unhide(self, status_icon, data=None):
    self.window.deiconify()

  def delete_event(self, widget, data=None):
    print "delete event occurred"
    return False

  def destroy(self, widget, data=None):
    gtk.main_quit()

  def change_dev(self, item, dev):
    self.pyh3c.h3cStatus.dev = dev
    print "Changed to " + self.pyh3c.h3cStatus.dev

  def user_name_changed(self, entry, data=None):
    self.pyh3c.h3cStatus.user_name = entry.get_text()
    return

  def user_pass_changed(self, entry, data=None):
    self.pyh3c.h3cStatus.user_pass = entry.get_text()
    return
  
  def dhcp_command_changed(self, entry, data=None):
    self.pyh3c.h3cStatus.dhcp_command = entry.get_text()
    return

  def ping_target_changed(self, entry, data=None):
    self.pyh3c.h3cStatus.ping_target = entry.get_text()
    return

  def save_config(self, widget, data=None):
    self.pyh3c.h3cStatus.save_config()
    return

  class STATUS_OUTPUT:
    def __init__(self, h3c_gui):
      self.h3c_gui = h3c_gui

    def write(self, text):
      self.h3c_gui.buffer_status.insert(self.h3c_gui.buffer_status.get_end_iter(), text)

    def writelines(self, lines):
      for line in lines: 
        self.write(line)

  def pyh3c_output_passer(self, output=None):
    #while True:
      out = self.pyh3c_instance.stdout.readline()
      #if not out: continue
      if out:
        self.status_output.write(out)
      return True

class H3C_GUI_ICON(gtk.StatusIcon):
  def __init__(self):
    gtk.StatusIcon.__init__(self)



if __name__ == "__main__":


  h3c_gui = H3C_GUI()

  h3c_gui_icon = H3C_GUI_ICON()
  h3c_gui_icon.connect("activate", h3c_gui.unhide)


  gtk.main()
  #gtk.main_iteration_do()
