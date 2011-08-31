#!/usr/bin/env python

import pygtk
pygtk.require('2.0')
import gtk

import pcap
import dpkt
import binascii
import dnet
import commands
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

def create_MenuItem(name, callback, data=None):
  item = gtk.MenuItem(name)
  item.connect("activate", callback, data)
  item.show()
  return item

def create_OptionMenu(menu):
  opt = gtk.OptionMenu()
  opt.set_menu(menu)
  opt.show()
  return opt

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
def change_eth(item, eth):
  print "Changed to " + eth


class H3C_GUI:
  def __init__(self):
    self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
    self.window.show()

    #register signals with handlers
    self.window.connect("delete_event", self.delete_event)
    self.window.connect("destroy", self.destroy) 
    self.window.set_border_width(20)

    #setup boxes
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
    #endof labels

    #setup entry
    self.entry_user = create_Entry(0, "houqp")
    self.entry_pass = create_Entry(0, None)
    self.entry_pass.set_visibility(gtk.FALSE)
    self.entry_dhcp = create_Entry(0, None)
    #endof entry
  
    #setup OptionMenus
    menu_eth = gtk.Menu()
    item = create_MenuItem("eth0", change_eth, "eth0")
    menu_eth.append(item)
    item = create_MenuItem("wlan0", change_eth, "wlan0")
    menu_eth.append(item)
    opt_eth = create_OptionMenu(menu_eth)
    #endof OptionMenus

    #setup buttons
    button_connect = create_Button("Connect")
    button_connect.connect("clicked", self.pressed_connect, None)

    button_disconnect = create_Button("Disconnect")
    button_disconnect.connect("clicked", self.pressed_disconnect, None)

    button_hide = create_Button("Hide me!")
    button_hide.connect("clicked", self.pressed_hide, None)

    button_exit = create_Button("Quit", gtk.STOCK_QUIT)
    button_exit.connect_object("clicked", gtk.Widget.destroy, self.window)

    button_about = create_Button("About", gtk.STOCK_DIALOG_INFO)
    button_about.connect("clicked", self.hello, None)
    #endup buttons

    #setup frames
    frame_config = create_Frame("Configuration:")
    frame_status = create_Frame("Connection status:")
    #endof frames

    #setup TextView
    welcome_text = """
[*] Activities from server.
[#] Activities from client.
[!] Messages you may want to read.

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
    self.window.add(box_main)
    #-----------------------------
    box_main.pack_start(frame_config, False, False, 10)
    box_main.pack_start(frame_status, True, True, 10)
    box_main.pack_start(hsep_status, False, False, 10)
    box_main.pack_start(box_buttons, False, False, 10)
    #-----------------------------
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
    table_config.attach(opt_eth, 1, 2, 2, 3, gtk.FILL, gtk.FILL, 0, 0)

    table_config.attach(label_dhcp, 0, 1, 3, 4, gtk.FILL, gtk.FILL, 0, 0)
    table_config.attach(self.entry_dhcp, 1, 2, 3, 4, gtk.FILL, gtk.FILL, 0, 0)
    #box_config.pack_start(entry_user, False, False, 0)

    frame_status.add(textview_sw_status)

    box_buttons.pack_start(button_connect, False, False, 5)
    box_buttons.pack_start(button_disconnect, False, False, 5)
    box_buttons.pack_start(button_hide, False, False, 5)
    box_buttons.pack_end(button_about, False, False, 5)
    box_buttons.pack_end(button_exit, False, False, 5)
    #endof packing

  def hello(self, widget, data=None):
    about_messg = """
PyH3C is a freesoftware! You can download 
the source code at:
https://github.com/houqp/pyh3c
Happy hacking :-)

This piece of software may not be working
as you expected. But if it really works,
remember to send me a Thank you letter via
qingping.hou@gmail.com.

OK, I am just kidding. Forget about this.

Author: houqp
"""
    show_dialog("About", about_messg)

  def pressed_connect(self, widget, data=None):
    if not (getuid() == 0):
      privilege_warn = " You must run with root privilege!"
      show_dialog("Warnning", privilege_warn)
      return

    sender = dnet.eth(h3cStatus.dev)
    client_hwadd = sender.get()
   
    def send_start_callback_gui():
      buf = "[*] Sent out the authentication request."
      self.buffer_status.insert(self.buffer_status.get_end_iter(), buf)

    send_start(sender, send_start_callback_gui)
    pcap_thread = threading.Thread(None, pcap_loop, "pcap_thread", h3c_gui)
    pcap_thread.start()
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

  def identity_handler_callback_gui(self):
    if h3cStatus.auth_success:
      print " [*] Received server check online request, sent keepalive packet."
    else:
      print " [*] Received identity challenge request."
      print "     [#] Sent identity challenge response."

  def h3c_unknown_handler_callback(self):
    print " [*] Received unknown h3c response from server."

  def allocated_handler_callback(self):
    print " [*] Received allocated challenge request."
    print "     [#] Sent allocated challenge response."

  def success_handler_callback(self):
    dhcp_command = "%s %s" % (h3cStatus.dhcp_script, h3cStatus.dev)
    print ""
    print "  /---------------------------------------------\ "
    print " | [^_^] Successfully passed the authentication! |"
    print "  \---------------------------------------------/ "
    print ""
    print " [#] running command: %s to get an IP." % dhcp_command
    print ""
    (status, output) = commands.getstatusoutput(dhcp_command)
    print output
    print ""
    print " [!] Every thing is done now, happy surfing the Internet." 
    print " [!] I will send heart beat packets to keep you online." 

  def failure_handler_callback(self):
    print " [*] Received authentication failed packet from server."
    print "     [#] Try to restart the authentication."
    send_start()

def pcap_loop(self):
  show_dialog("Warnning", "hahahaha")

  hw_s = binascii.b2a_hex(client_hwadd)
  filter_hwadd = "%s:%s:%s:%s:%s:%s" % (hw_s[0:2], hw_s[2:4], hw_s[4:6], hw_s[6:8], hw_s[8:10], hw_s[10:12])

  filter = 'ether host %s and ether proto 0x888e' % filter_hwadd
  pc = pcap.pcap(h3cStatus.dev)
  pc.setfilter(filter)

  for ptime,pdata in pc:
    ether = dpkt.ethernet.Ethernet(pdata)
    if ether.dst == client_hwadd:
      radius = RADIUS_H3C(ether.data)
      eap = RADIUS_H3C.EAP(radius.data)

      if response_type[eap.code] == 'request':
        handler = "%s_handler" % eap_type[eap.type]
      else:
        handler = "%s_handler" % response_type[eap.code]
      hander_callback = "%s_callback" % handler
      globals()[handler](ether, sender, getattr(self, hander_callback), self)

class H3C_GUI_ICON(gtk.StatusIcon):
  def __init__(self):
    gtk.StatusIcon.__init__(self)


if __name__ == "__main__":

  h3c_gui = H3C_GUI()

  h3c_gui_icon = H3C_GUI_ICON()
  h3c_gui_icon.connect("activate", h3c_gui.unhide)


  h3cStatus.load_config()
  h3c_gui.entry_user.set_text(h3cStatus.user_name)
  h3c_gui.entry_pass.set_text(h3cStatus.user_pass)
  h3c_gui.entry_dhcp.set_text(h3cStatus.dhcp_script)

  pcap_loop(h3c_gui)

  gtk.main()
