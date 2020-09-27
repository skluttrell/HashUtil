import collections, hashlib, playsound, pyperclip, sys, threading, time, wx

# Creates a wx event handler
myEVT_HASHER = wx.NewEventType()
EVT_HASHER = wx.PyEventBinder(myEVT_HASHER, 1)

class HasherEvent(wx.PyCommandEvent):
	""" Event to signal that a count event is ready """

	def __init__(self, etype, eid, value=None):
		""" Creates the event object """
		wx.PyCommandEvent.__init__(self, etype, eid)
		self._value = value

	def GetValue(self):
		""" Returns the value from the event.
		@retur: the value of this event
		"""

		return self._value

class HasherThread(threading.Thread):
	def __init__(self, parent, algorithm, iFile):
		"""
		@param parent: the gui object that should recieve the value
		@param lgorithm: the algorithm to use to encode the file
		@param iFile: the file to be encoded
		"""
		threading.Thread.__init__(self, daemon=True)
		self._parent = parent
		self._algorithm = algorithm
		self._iFile = iFile

	def run(self):
		""" Overrides Thread.run. Don't call this directly. It's called internally
		when you call Thread.start().
		"""

		hash = None
		monitor = MonitorThread()
		monitor.start()

		if self._algorithm == 'blake2b': hash = hashlib.blake2b()
		elif self._algorithm == 'blake2s': hash = hashlib.blake2s()
		elif self._algorithm == 'pbkdf2_hmac': hash = hashlib.pbkdf2_hmac()
		elif self._algorithm == 'md5': hash = hashlib.md5()
		elif self._algorithm == 'sha1': hash = hashlib.sha1()
		elif self._algorithm == 'sha224': hash = hashlib.sha224()
		elif self._algorithm == 'sha256': hash = hashlib.sha256()
		elif self._algorithm == 'sha384': hash = hashlib.sha384()
		elif self._algorithm == 'sha3_224': hash = hashlib.sha3_224()
		elif self._algorithm == 'sha3_256': hash = hashlib.sha3_256()
		elif self._algorithm == 'sha3_384': hash = hashlib.sha3_384()
		elif self._algorithm == 'sha3_512': hash = hashlib.sha3_512()
		elif self._algorithm == 'sha512': hash = hashlib.sha512()
		elif self._algorithm == 'shake_128': hash = hashlib.shake_128()
		elif self._algorithm == 'shake_256': hash = hashlib.shake_256()

		with open(self._iFile, 'rb') as f:
			for block in iter(lambda: f.read(4096), b""):
				hash.update(block)

		evt = HasherEvent(myEVT_HASHER, -1, hash.hexdigest())
		monitor.join()
		wx.PostEvent(self._parent, evt)

class MonitorThread(threading.Thread):
	""" Plays a sound when the processor is working on a file hash """

	def __init__(self, *args, **qwargs):
		threading.Thread.__init__(self)
		self._stopEvent = threading.Event()

	def run(self):
		playsound.playsound('accessing.wav')
		while not self._stopEvent.isSet():
			playsound.playsound('processing.wav')

	def join(self, timeout=None):
		""" Stop the thread """

		self._stopEvent.set()
		threading.Thread.join(self, timeout)

class Window(wx.Frame):
	# Initialize the main program window (frame)
	def __init__(self, parent, title):
		super(Window, self).__init__(parent, title=title)
		self.UI()
		self.Center()
		self.Show() # Start the main window (frame)

	def UI(self):
		panel = wx.Panel(self)
		mainSizer = wx.BoxSizer(wx.VERTICAL)
		controlsSizer = wx.BoxSizer(wx.HORIZONTAL)
		hashDisplaySizer = wx.BoxSizer(wx.HORIZONTAL)
		self.iFile = '' # The file to be calculated

		# Initialize the user interface elements
		types = [ 'blake2b', 'blake2s',	 'pbkdf2_hmac', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'sha512', 'shake_128', 'shake_256' ]
		self.hashLabelText = wx.StaticText(panel, label='Hash:')
		self.hashDisplayText = wx.StaticText(panel)
		self.getFileButton = wx.Button(panel, label='select file') # Open the file
		self.hashTypesComboBox = wx.ComboBox(panel, choices=types)
		self.checkButton = wx.Button(panel, label='check') # Check a hash from the clipboard
		self.refreshButton = wx.Button(panel, label='refresh') # Add a new library path
		self.copyHashButton = wx.Button(panel, label='copy to clipboard') # Open the file
		self.exitButton = wx.Button(panel, label='Exit') # Closes the app without committing any changes
		self.getFileButton.SetFocus() # Set this button as the focus when the app opens
		self.hashTypesComboBox.SetSelection(0) # Set the default selection on the first choice

		# link the elements to the sizers
		controlsSizer.Add(self.getFileButton, 0)
		controlsSizer.Add(self.hashTypesComboBox, 0)
		controlsSizer.Add(self.checkButton, 0)
		controlsSizer.Add(self.refreshButton, 0)
		controlsSizer.Add(self.copyHashButton, 0)
		controlsSizer.Add(self.exitButton, 0)
		hashDisplaySizer.Add(self.hashLabelText, 0)
		hashDisplaySizer.Add(self.hashDisplayText, 0)
		mainSizer.Add(controlsSizer, 0)
		mainSizer.Add(hashDisplaySizer, 0)

		# Bind the event listeners to their respective controls
		self.getFileButton.Bind(wx.EVT_BUTTON, self.OnOpen)
		self.checkButton.Bind(wx.EVT_BUTTON, self.OnCheck)
		self.refreshButton.Bind(wx.EVT_BUTTON, self.OnRefresh)
		self.copyHashButton.Bind(wx.EVT_BUTTON, self.OnCopy)
		self.exitButton.Bind(wx.EVT_BUTTON, self.OnExit)
		self.Bind(EVT_HASHER, self.OnGetHash)

		# Set the sizer size and position
		panel.SetSizer(mainSizer)

	# The event handlers
	def OnCheck(self, e):
		""" Checks the current file against a checksum on the clipboard """

		cbText = pyperclip.paste()
		if cbText:
			if cbText == self.hashDisplayText.GetLabel(): msg = wx.MessageDialog(self, 'The checksum matches.', 'Alert!', wx.OK)
			else: msg = wx.MessageDialog(self, 'The checksum does not match. Did you copy the right hash and select the right algorithm?', 'Alert!', wx.OK)
		else:
			msg = wx.MessageDialog(self, 'There is nothing copied to the clipboard.', 'Alert!', wx.OK)

		with msg as m:
			m.ShowModal()

	def OnRefresh(self, e):
		""" Re-acquires the  hash and displays it """

		self.ProcessFile()

	def OnCopy(self, e):
		""" Copy hash to clipboard """

		pyperclip.copy(self.hashDisplayText.GetLabel())

	def OnOpen(self, e):
		""" Opens a file to be calculated. """

		with wx.FileDialog(self, 'select file', style=wx.DD_DEFAULT_STYLE) as dlg:
			if dlg.ShowModal() == wx.ID_OK:
				self.iFile = dlg.GetPath()
				self.ProcessFile()

	def OnExit(self, e):
		""" Shuts down the program. """

		self.Close(True) # Close the frame
		sys.exit(0)

	def OnGetHash(self, evt):
		""" Places the hash text in the display text box """

		val = evt.GetValue()
		self.hashDisplayText.SetLabel(val)

	def ProcessFile(self):
		""" Runs the calculation thread """

		self.hashDisplayText.SetLabel("") # Empty the display text box
		worker = HasherThread(self, self.hashTypesComboBox.GetValue(), self.iFile)
		worker.start()

app = wx.App(False) # Creates a new app and does not redirect stdout or stderr
frame = Window(None, 'HashUtil') # A frame is a top level window
app.MainLoop()