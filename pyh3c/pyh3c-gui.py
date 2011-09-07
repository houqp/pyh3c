#!/usr/bin/env python

import pygtk
pygtk.require('2.0')
import gtk
import gobject
import threading
import Queue

import pcap
import dpkt
import binascii
import dnet
import subprocess
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
    #@TODO@ 
    # check root privilege here!

    gobject.threads_init()

    self.dataQueue = Queue.Queue()
    self.auth_loop_started = False
    self.connection_started = False
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
    button_save_config = create_Button("Save Configuration")
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
    frame_config = create_Frame("Configuration")
    frame_config.set_label_align(0.5,0)
    frame_status = create_Frame("Connection status")
    frame_status.set_label_align(0.5,0)
    #endof frames

    #setup TextView
    welcome_text = """
"""
    textview_status = create_TextView(welcome_text)
    textview_status.set_size_request(width=520, height=200)
    self.textview_sw_status = create_ScrolledWindow()
    self.textview_sw_status.add(textview_status)
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
    box_root.pack_start(box_main, True, True, 0)
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
    frame_status.add(self.textview_sw_status)

    # start of buttons
    box_buttons.pack_start(button_connect, False, False, 5)
    box_buttons.pack_start(button_disconnect, False, False, 5)
    box_buttons.pack_start(button_hide, False, False, 5)
    box_buttons.pack_end(button_quit, False, False, 5)
    #endof packing

    #===================================
    # do some real initialization now
    #===================================
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

    self.status_output = self.STATUS_OUTPUT(self)


    gobject.timeout_add(100, self.queue_checker)

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
    if not self.auth_loop_started:
      auth_t = threading.Thread(group=None, target=self.auth_loop, name='auth_t')
      auth_t.daemon = True
      auth_t.start()
      self.auth_loop_started = True
    else:
      send_t = threading.Thread(group=None, target=self.pyh3c.send_start, name='send_start')
      send_t.daemon = True
      send_t.start()
      send_t.join()
      self.dataQueue.put((self.send_start_gui_update, None))
      #self.send_start_gui_update()

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

  def queue_checker(self):
    try:
      gui_updater, data = self.dataQueue.get(block=False)
      if data:
        gui_updater(data)
      else:
        gui_updater()
      #self.scrolled_to_window_bottom()
    except Queue.Empty:
      pass
    return True

  def scrolled_to_window_bottom(self):
    adj = self.textview_sw_status.get_vadjustment()
    adj.set_value(adj.get_upper() - adj.get_page_size())

  def hello_world_gui_update(self):
    self.status_output.write("[*] Activities from server.\n")
    self.status_output.write("[#] Activities from client.\n")
    self.status_output.write("[!] Messages you may want to read.\n")
    self.status_output.write("\n")
    self.status_output.write("[!] Using user name: %s\n" % self.pyh3c.h3cStatus.user_name)
    self.status_output.write("[!] Using interface: %s\n" % self.pyh3c.h3cStatus.dev)
    self.status_output.write("[!] Using DHCP script: %s\n" % self.pyh3c.h3cStatus.dhcp_command)
    self.status_output.write("\n")
    self.scrolled_to_window_bottom()

  def send_start_gui_update(self):
    self.status_output.write("[*] Sent out the authentication request.\n")
    self.scrolled_to_window_bottom()

  def identity_gui_update(self, ether):
    if self.pyh3c.h3cStatus.auth_success:
      self.status_output.write("[*] Received server check online request, sent response packet.\n")
    else:
      self.status_output.write("[*] Received identity challenge request.\n")
      self.status_output.write("    [#] Sent identity challenge response.\n")
    self.scrolled_to_window_bottom()

  def h3c_unknown_gui_update(self, ether):
    self.status_output.write(" [*]Received unknown h3c response from server.\n")
    self.scrolled_to_window_bottom()

  def allocated_gui_update(self, ether):
    self.status_output.write("[*] Received allocated challenge request.\n")
    self.status_output.write("    [#] Sent allocated challenge response.\n")
    self.scrolled_to_window_bottom()

  def success_gui_update(self, ether):
    self.status_output.write("\n")
    self.status_output.write(" /---------------------------------------------\ \n")
    self.status_output.write("| [^_^] Successfully passed the authentication! |\n")
    self.status_output.write(" \---------------------------------------------/ \n")
    self.status_output.write("\n")

    #@TODO: check operating system here
    dhcp_command = "%s %s" % (self.pyh3c.h3cStatus.dhcp_command, self.pyh3c.h3cStatus.dev)
    #@TODO@: use subprocess here
    (status, output) = commands.getstatusoutput(dhcp_command)
    self.status_output.write("[#] running command: %s to get an IP.\n" % dhcp_command)
    self.status_output.write("\n")
    self.status_output.write(output)
    self.status_output.write("\n")

    self.status_output.write("[!] Every thing is done now, happy surfing the Internet.\n")
    self.status_output.write("[!] I will send heart beat packets to keep you online.\n")
    self.scrolled_to_window_bottom()

  def failure_gui_update(self, ether):
    self.status_output.write("[*] Received authentication failed packet from server.\n")
    radius = RADIUS_H3C(ether.data)
    eap = RADIUS_H3C.EAP(radius.data)
    error = eap.data[1:7]
    try:
      self.status_output.write("[*] Error code: \"%s\", %s\n" % (error, error_code[error]))
    except KeyError:
      self.status_output.write("[*] Error code: \"%s\", %s\n" % (binascii.b2a_hex(error), "Unknown error code!"))
      self.status_output.write("    Please fire a bug report at:\n")
      self.status_output.write("    https://github.com/houqp/pyh3c/issues\n")
    self.status_output.write("    [#] Try to restart the authentication in one second.\n")
    self.scrolled_to_window_bottom()
  
  def wtf_gui_update(self, tuple):
    ether, eap = tuple
    self.status_output.write("[!] Encountered an unknown packet!\n")
    self.status_output.write("[!] ----------------------------------------\n")
    self.status_output.write("\n")
    self.pyh3c.debug_packets(ether, eap)
    self.status_output.write("\n")
    self.status_output.write("* It may be sent from some aliens, please help improve\n")
    self.status_output.write("  software by fire a bug report at:\n")
    self.status_output.write("  https://github.com/houqp/pyh3c/issues\n")
    self.status_output.write("  Also remember to paste the above output in your report.\n")
    self.status_output.write("[!] ----------------------------------------\n")
    self.scrolled_to_window_bottom()

  def auth_loop(self):

    def hello_world(pyh3c):
      self.dataQueue.put((self.hello_world_gui_update, None))
    
    def send_start_callback(pyh3c):
      self.dataQueue.put((self.send_start_gui_update, None))

    def identity_handler_callback(ether, pyh3c):
      self.dataQueue.put((self.identity_gui_update, ether))

    def h3c_unknown_handler_callback(ether, pyh3c):
      self.dataQueue.put((self.h3c_unknown_gui_update, ether))

    def allocated_handler_callback(ether, pyh3c):
      self.dataQueue.put((self.allocated_gui_update, ether))
      pass

    def success_handler_callback(ether, pyh3c):
      self.dataQueue.put((self.success_gui_update, ether))
      pass

    def failure_handler_callback(ether, pyh3c):
      self.dataQueue.put((self.failure_gui_update, ether))
      pass
    
    def wtf_handler_callback(ether, pyh3c, eap):
      self.dataQueue.put(
          (self.wtf_gui_update, (ether, eap))
          )

    callbacks = {
        "hello_world": hello_world,
        "send_start_callback": send_start_callback,
        "identity_handler_callback": identity_handler_callback,
        "h3c_unknown_handler_callback": h3c_unknown_handler_callback,
        "allocated_handler_callback": allocated_handler_callback,
        "success_handler_callback": success_handler_callback,
        "failure_handler_callback": failure_handler_callback,
        "wtf_handler_callback": wtf_handler_callback
        }

    send_start_callback(self.pyh3c)
    sleep(1)
    identity_handler_callback(1, self.pyh3c)
    sleep(1)
    h3c_unknown_handler_callback(1, self.pyh3c)
    sleep(1)
    allocated_handler_callback(1, self.pyh3c)
    sleep(1)
    #success_handler_callback(1, self.pyh3c)
    #sleep(1)
    #failure_handler_callback(1, self.pyh3c)
    send_start_callback(self.pyh3c)
    send_start_callback(self.pyh3c)
    send_start_callback(self.pyh3c)
    send_start_callback(self.pyh3c)
    send_start_callback(self.pyh3c)
    send_start_callback(self.pyh3c)
    send_start_callback(self.pyh3c)
    send_start_callback(self.pyh3c)
    send_start_callback(self.pyh3c)

    self.pyh3c.main(callbacks)

 
class H3C_GUI_ICON(gtk.StatusIcon):
  def __init__(self):
    gtk.StatusIcon.__init__(self)



if __name__ == "__main__":


  h3c_gui = H3C_GUI()

  h3c_gui_icon = H3C_GUI_ICON()
  h3c_gui_icon.connect("activate", h3c_gui.unhide)


  gtk.main()
  #gtk.main_iteration_do()
