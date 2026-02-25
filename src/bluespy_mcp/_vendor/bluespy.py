## @file bluespy.py
"""blueSPY Python API

API for controlling blueSPY from python.

Provides functions for connecting to a moreph and loading existing captures.
Also provides a 'packets' object, which behaves like a list and can be used to access
the packets in the current file.
len(packets) shows the number of available packets, packets[0] accesses the first packet.
The queries documented in the GUI can be accessed with attribute syntax, e.g. packets[0].summary

Examples:
To connect to a moreph with serial 00010100 and capture CL and LE:

    import bluespy
    from time import sleep

    bluespy.connect(0x00010100)
    bluespy.capture("example.pcapng", CL=True, LE=True)
    sleep(20)
    bluespy.stop_capture()
    bluespy.disconnect()
    print("Captured {} packets".format(len(bluespy.packets)))
    bluespy.close_file()


To load an existing capture and print the summary strings of all packets:

    import bluespy

    bluespy.load_file("example.pcapng")
    for p in bluespy.packets:
        print(p.summary)
    bluespy.close_file()

"""

import ctypes as _ct
import atexit

import platform
import os

_path = ""
_library_path = ""
_path_found = False

if "BLUESPY_LIBRARY_PATH" in os.environ:
    _path = os.environ["BLUESPY_LIBRARY_PATH"]
    _library_path = _path
    _path_found = True

if not os.path.isfile(_path):
    if platform.system() == "Windows":
        _name = "libblueSPY.dll"
    elif platform.system() == "Linux":
        _name = "libblueSPY.so"
    elif platform.system() == "Darwin":
        _name = "../Frameworks/libblueSPY.dylib"

    if os.path.isdir(_path):
        _path = os.path.abspath(os.path.join(_path, _name))
    else:
        _path = os.path.abspath(os.path.join(os.path.dirname(__file__), _name))

    if not os.path.isfile(_path):
        _path = _name  # Try the LoadLibrary default paths

try:
    _libbluespy = _ct.cdll.LoadLibrary(_path)
except FileNotFoundError as e:
    if _path_found:
        raise FileNotFoundError(
            "BLUESPY_LIBRARY_PATH("+_library_path+") does not lead to libblueSPY, please set BLUESPY_LIBRARY_PATH correctly in the environment"
        ) from e
    else:
        raise FileNotFoundError(
            "libblueSPY not found, please set BLUESPY_LIBRARY_PATH in the environment"
        ) from e

class error(_ct.c_int):
    """! Return type showing why an operation failed.

    Evaluates to True if the operation succeeded, else False.
    str() and repr() give an error string, .value gives an error code.
    """

    def __str__(self):
        return _libbluespy.bluespy_error_string(self.value).decode("utf-8")

    def __repr__(self):
        return "{}: {}".format(self.value, self.__str__()) if self.value else ""

    def __bool__(self):
        return self.value == 0

class blueQ_testcase_verdict(_ct.c_int):
    """! Testcase verdict

    Evaluates to True if the testcase passed, else False.
    str() and repr() give an error string, .value gives an error code.
    """

    def __str__(self):
        return _libbluespy.blueQ_testcase_verdict_string(self.value).decode("utf-8")

    def __repr__(self):
        return "{}: {}".format(self.value, self.__str__())

    def __bool__(self):
        return self.value == 0

class blueQ_verbosity(_ct.c_int):
    """! Verbosity of print statements during blueQ run
    """

    def __str__(self):
        return _libbluespy.blueQ_verbosity_string(self.value).decode("utf-8")

    def __repr__(self):
        return "{}: {}".format(self.value, self.__str__())

class blueQ_serial_flow_control(_ct.c_int):
    """! Options for flow control when connecting to an IUT serial port
    """

class blueQ_serial_parity_bits(_ct.c_int):
    """! Options for parity bits when connecting to an IUT serial port
    """

class blueQ_serial_stop_bits(_ct.c_int):
    """! Options for parity bits when connecting to an IUT serial port
    """

class log_level(_ct.c_int):
    """! Return log level"""
    PASS = 0x00
    WARN = 0x20
    INFO = 0x40
    DEBUG = 0x60
    ERROR = 0x80

class logic_rate(_ct.c_int):
    """! Return logic rate"""
    high = 0
    medium = 1
    rate = 2

class BluespyError(RuntimeError):
    """! Exception showing why an operation failed."""

    def get_error(self):
        """Return the underlying error object."""
        return self.args[0]

def _handle_error(err):
    if err.value:
        raise BluespyError(err)

def connect(serial=-1):
    """! Connect to Moreph hardware via USB or Ethernet.

    @param serial: A serial number as an integer, or -1 to connect to the first device.
    The serial number shown in the software and on the MiniMoreph is hexadecimal, so should be entered as 0xNNNNNN.
    There is a serial number on the bottom of some Moreph30s is of the form AYYYY-XXXXX, the XXXXX is the required serial number in decimal.

    @exception BluespyError: Exception in the bluespy library

    You should run disconnect() later if this is successful.
    """

    _handle_error(_libbluespy.bluespy_connect(serial))

def blueQ_connect(serial=-1):
    """! Connect to Moreph hardware via USB or Ethernet, in blueQ mode.

    @param serial: A serial number as an integer, or -1 to connect to the first USB device.
    The serial number shown in the software and on the MiniMoreph is hexadecimal, so should be entered as 0xNNNNNN.
    There is a serial number on the bottom of some Moreph30s is of the form AYYYY-XXXXX, the XXXXX is the required serial number in decimal.

    @exception BluespyError: Exception in the bluespy library

    You should run disconnect() later if this is successful.
    """

    _handle_error(_libbluespy.blueQ_connect(serial))


def connect_multiple(serials):
    """! Connect to multiple Moreph hardware devices via USB or Ethernet.

    @param serials: An array of serial numbers as integers.
    The first serial number in the array is considered that of the primary device.
    The serial numbers shown in the software and on the MiniMoreph are hexadecimal, so should be entered as 0xNNNNNN.
    There is a serial number on the bottom of some Moreph30s is of the form AYYYY-XXXXX, the XXXXX is the required serial number in decimal.

    @exception BluespyError: Exception in the bluespy library

    You should run disconnect() later if this is successful.
    """
    u32list = _ct.c_uint32 * len(serials)
    serial_span = u32list()
    for i in range(len(serials)):
        serial_span[i] = serials[i]
    _handle_error(_libbluespy.bluespy_connect_multiple(serial_span, len(serials)))

def connected_morephs():
    """! Get the serial numbers of connected moreph devices.

    @return: Array of serial numbers
    """
    uint32_ptr = _ct.POINTER(_ct.c_uint32)
    hw_data = uint32_ptr()
    hw_count = _libbluespy.bluespy_morephs_connected(_ct.byref(hw_data))

    return [hw_data[i] for i in range(hw_count)]

def disconnect():
    """! Disconnect from the connected Morephs

    @exception BluespyError: Exception in the bluespy library"""
    atexit.unregister(stop_capture)
    atexit.unregister(disconnect)
    _handle_error(_libbluespy.bluespy_disconnect())

def reboot_moreph(serial=-1):
    """! Reboot Moreph hardware via USB or Ethernet.

    @param serial: A serial number as an integer, or -1 to connect to the first device.
    The serial number shown in the software and on the MiniMoreph is hexadecimal, so should be entered as 0xNNNNNN.
    There is a serial number on the bottom of some Moreph30s is of the form AYYYY-XXXXX, the XXXXX is the required serial number in decimal.

    @exception BluespyError: Exception in the bluespy library

    This function will cause the specified Moreph to disconnect - bluespy.connect(serial) needs to be called
    afterwards to talk to the Moreph again
    """
    _handle_error(_libbluespy.bluespy_moreph_reboot(serial))

class time_point(_ct.c_int64):
    """! Represents the time in nanoseconds since epoch 1970/01/01 00:00 UTC"""

    def __init__(self, ts=0x7fffffffffffffff):
        self.value = ts

    def __bool__(self):
        """! Returns if it's a valid time"""
        return self.value != 0x7fffffffffffffff

    def __str__(self):
        """! Returns the string representation of the time"""
        return _libbluespy.bluespy_print_time(self).decode("utf-8")

def invalid_time():
    """! Invalid time point

    @return: invalid time point"""
    return time_point()

def add_log_message(level, message, ts=0x7fffffffffffffff):
    """! Adds a log message into the running capture

    @param level: The Log Level.
    @param message: The log message content.
    @param ts: The time of the log message. ts=invalid means the time will be set to the present.

    @exception BluespyError: Exception in the bluespy library"""
    _handle_error(_libbluespy.bluespy_add_log_message(level, message.encode("utf-8"), ts))

class audio_channel(_ct.c_int):
    STEREO = 0
    MONO_L = 1
    MONO_R = 2

class audio_connect(_ct.c_int):
    NOAUDIO = 0
    LINE = 1
    JACK = 2
    HEADSET = 3
    COAX = 4
    OPTICAL = 5
    MIC = 6
    I2S = 7

class audio_bias(_ct.c_int):
    OFF = 0
    LOW = 1
    MID = 2
    HIG = 3
    VDD = 4

class audiopod_options(object):
    """! Audiopod capture options"""
    def __init__(self,
        channels=audio_channel.STEREO,
        output=audio_connect.NOAUDIO,
        input=audio_connect.NOAUDIO,
        bias=audio_bias.OFF,
        sample_rate=0,
        current_probe=False,
        LA_low_voltage = 0.0,
        LA_high_voltage = 0.0,
        power_supply_V=0.0,
        VIO_dV = 0.0,
        second_I2S_input=False,
        AGC=False,
        DRC=False,
        vol_in_left = 0.0,
        vol_in_right = 0.0,
        vol_out_left = 0.0,
        vol_out_right = 0.0,
    ):
        """
        @param channels: Audiopod Channels
        @param output: Which audiopod port is used for output
        @param input: Which audiopod port is used for intput
        @param bias: Audiopod bias
        @param sample_rate: Audiopod sample rate
            Allowed values are: 8'000, 11'025, 16'000, 22'050, 32'000, 44'100, 48'000, 88'200, 96'000, 176'400, 192'000
        @param current_probe: Enable current probe
        @param LA_low_voltage: Logic Low Voltage. Must be within the [0.0, 3.3] range.
        @param LA_high_voltage: Logic High Voltage. Must be within the [0.0, 3.3] range.
            Allowed values for Audiopod_Logic(Low/High)Voltage are from 0.0 to 3.3
        @param power_supply_V: Power supply in volts
            Allowed values are from 0.6 to 5.0
        @param VIO_dV: VIO in deciVolts
        @param second_I2S_input: Enable a second I2S input, output must be set to BLUESPY_NO_AUDIO
        @param AGC: AGC
        @param DRC: DRC
        @param vol_in_left: Input volume (Left)
        @param vol_in_right: Input volume (Right)
        @param vol_out_left: Output volume (Left)
        @param vol_out_right: Output volume (Right)
        """
        object.__setattr__(self, "p", _libbluespy.bluespy_capture_audiopod_options_alloc())
        self.p.contents.sample_rate = sample_rate
        self.p.contents.channels = channels
        self.p.contents.output = output
        self.p.contents.input = input
        self.p.contents.bias = bias
        self.p.contents.current_probe = current_probe
        self.p.contents.LA_low_voltage = LA_low_voltage
        self.p.contents.LA_high_voltage = LA_high_voltage
        self.p.contents.power_supply_V = power_supply_V
        self.p.contents.VIO_dV = VIO_dV
        self.p.contents.second_I2S_input = second_I2S_input
        self.p.contents.AGC = AGC
        self.p.contents.DRC = DRC
        self.p.contents.vol_in_left = vol_in_left
        self.p.contents.vol_in_right = vol_in_right
        self.p.contents.vol_out_left = vol_out_left
        self.p.contents.vol_out_right = vol_out_right
    def __del__(self):
        _libbluespy.bluespy_delete(self.p)
    def __getattr__(self, name):
        if name == "p":
            return self.__getattribute__("p")
        return getattr(self.p.contents, name)
    def __setattr__(self, name, val):
        self.p.contents.__setattr__(name,val)

class i2s_options(object):
    """! I2S capture options"""
    def __init__(self,
        SCLK_line=0,
        WS_line=0,
        SD_line=0,
        n_channels=0,
        bits_per_ch=0,
        sample_on_rising_edge=False,
        first_chan_follows_WS_high=False,
        one_sample_delay=False,
        MSB_first=False,
        DSP_Mode=False,
        master=False,
    ):
        """
        @param SCLK: SCLK line for each interface. Valid values are [0,15]
        @param WS: WS line for each interface. Valid values are [0,15]
        @param SD: SD line for each interface. Valid values are [0,15]
        @param n_channels: Number of channels. Valid values are [1,16]
        @param bits_per_ch: Number of bits per channel. Valid values are [1,32]
        @param sample_on_rising_edge: Whether to sample on rising edges
        @param first_chan_follows_WS_high: Whether the first channel follows WS High
        @param one_sample_delay: Whether to delay by one sample
        @param MSB_first: MSB first
        @param DSP_Mode: DSP Mode
        @param Master: Master
        """
        object.__setattr__(self, "p", _libbluespy.bluespy_capture_i2s_options_alloc())
        self.p.contents.SCLK_line = SCLK_line
        self.p.contents.WS_line = WS_line
        self.p.contents.SD_line = SD_line
        self.p.contents.n_channels = n_channels
        self.p.contents.bits_per_ch = bits_per_ch
        self.p.contents.sample_on_rising_edge = sample_on_rising_edge
        self.p.contents.first_chan_follows_WS_high = first_chan_follows_WS_high
        self.p.contents.one_sample_delay = one_sample_delay
        self.p.contents.MSB_first = MSB_first
        self.p.contents.DSP_mode = DSP_Mode
        self.p.contents.master = master
    def __del__(self):
        _libbluespy.bluespy_delete(self.p)
    def __getattr__(self, name):
        if name == "p":
            return self.__getattribute__("p")
        return getattr(self.p.contents, name)
    def __setattr__(self, name, val):
        self.p.contents.__setattr__(name,val)

def capture(
    filename,
    CL=False,
    LE=False,
    QHS=False,
    _15_4=False,
    wifi=False,
    MHDT_CL=False,
    MHDT_LE=False,
    Dukosi=False,
    Varjo=False,
    CS=False,
    Audiopod=None,
    I2S = [None,None],
    spectrum=0,
    logic_mask=0x0000,
    logic_use_external_vref=True,
    logic_rate=0,
    HDT=False,
):
    """! Start a new capture in filename

    @param filename: Path to store capture in
    @param CL: Enable Bluetooth Classic capture
    @param LE: Enable Bluetooth LE capture
    @param QHS: Enable Qualcomm High Speed capture
    @param _15_4: Enable 802.15.4 capture
    @param wifi: Enable WiFi capture
    @param MHDT_CL: Enable MediaTek mHDT Classic capture
    @param MHDT_LE: Enable MediaTek mHDT LE capture
    @param Dukosi: Enable Dukosi capture
    @param Varjo: Enable Varjo capture
    @param CS: Enable Channel-Sounding capture

    @param Audiopod: Audiopod options. Providing an audiopod_options struct will enable audiopod
    @param I2S: I2S options. Providing i2s_options structs will enable I2S

    @param spectrum: Spectrum capture interval in microseconds. 0 means disabled.
        Allowed values are: 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000.
    @param logic_mask: 32-bit mask enabling logic lines
    @param logic_use_external_vref: Use External or Internal vref
    @param logic_rate: Low, Medium, or High logic rate

    @exception BluespyError: Exception in the bluespy library"""
    opts = _libbluespy.bluespy_capture_options_alloc()
    opts.contents.enable_CL = CL
    opts.contents.enable_LE = LE
    opts.contents.enable_HDT = HDT
    opts.contents.enable_QHS = QHS
    opts.contents.enable_15_4 = _15_4
    opts.contents.enable_wifi = wifi
    opts.contents.enable_MHDT_CL = MHDT_CL
    opts.contents.enable_MHDT_LE = MHDT_LE
    opts.contents.enable_Dukosi = Dukosi
    opts.contents.enable_Varjo = Varjo
    opts.contents.enable_Channel_Sounding = CS
    opts.contents.spectrum_period = spectrum
    opts.contents.logic_mask = logic_mask
    opts.contents.logic_use_external_vref = logic_use_external_vref
    opts.contents.logic_rate = logic_rate

    if Audiopod != None:
        opts.contents.audiopod_opts = Audiopod.p

    for i in range(2):
        if I2S[i] != None:
            opts.contents.i2s_opts[i] = I2S[i].p

    _handle_error(
        _libbluespy.bluespy_capture(
            filename.encode("utf-8"), opts,
        )
    )
    _libbluespy.bluespy_delete(opts)
    atexit.register(close_file)
    atexit.register(stop_capture)

def capture_multiple(

    filename,
    CL=[],
    LE=[],
    wifi=[],
    QHS=False,
    _15_4=False,
    MHDT_CL=False,
    MHDT_LE=False,
    Dukosi=False,
    Varjo=False,
    CS=False,
    Audiopod=None,
    I2S = [None,None],
    spectrum=0,
    logic_mask=0x0000,
    logic_use_external_vref=True,
    logic_rate=0,
    HDT=[],
):
    """! Start a new capture in filename

    @param filename: Path to store capture in
    @param CL: Enable Bluetooth Classic capture, list of bools, one for each Moreph
    @param LE: Enable Bluetooth LE capture, list of bools, one for each Moreph
    @param wifi: Enable WiFi capture, list of bools, one for each Moreph
    @param QHS: Enable Qualcomm High Speed capture
    @param _15_4: Enable 802.15.4 capture
    @param MHDT_CL: Enable MediaTek mHDT Classic capture
    @param MHDT_LE: Enable MediaTek mHDT LE capture
    @param Dukosi: Enable Dukosi capture
    @param Varjo: Enable Varjo capture
    @param CS: Enable Channel-Sounding capture

    @param Audiopod: Audiopod options. Providing an audiopod_options struct will enable audiopod
    @param I2S: I2S options. Providing i2s_options structs will enable I2S

    @param spectrum: Spectrum capture interval in microseconds. 0 means disabled.
        Allowed values are: 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000.

    @exception BluespyError: Exception in the bluespy library"""

    opts = _libbluespy.bluespy_capture_options_alloc()

    if len(CL) > 0:
        opts.contents.enable_CL = CL[0]
        for i in range(1,min(len(CL),32)):
            opts.contents.multi_moreph_opts[i-1].enable_CL = CL[i]
    if len(LE) > 0:
        opts.contents.enable_LE = LE[0]
        for i in range(1,min(len(LE),32)):
            opts.contents.multi_moreph_opts[i-1].enable_LE = LE[i]
    if len(HDT) > 0:
        opts.contents.enable_HDT = HDT[0]
        for i in range(1,min(len(HDT),hw_count)):
            opts.contents.multi_moreph_opts[i-1].enable_HDT = HDT[i]
    if len(wifi) > 0:
        opts.contents.enable_wifi = wifi[0]
        for i in range(1,min(len(wifi),32)):
            opts.contents.multi_moreph_opts[i-1].enable_wifi = wifi[i]


    opts.contents.enable_QHS = QHS
    opts.contents.enable_15_4 = _15_4
    opts.contents.enable_MHDT_CL = MHDT_CL
    opts.contents.enable_MHDT_LE = MHDT_LE
    opts.contents.enable_Dukosi = Dukosi
    opts.contents.enable_Varjo = Varjo
    opts.contents.enable_Channel_Sounding = CS
    opts.contents.spectrum_period = spectrum
    opts.contents.logic_mask = logic_mask
    opts.contents.logic_use_external_vref = logic_use_external_vref
    opts.contents.logic_rate = logic_rate

    if Audiopod != None:
        opts.contents.audiopod_opts = Audiopod.p

    for i in range(2):
        if I2S[i] != None:
            opts.contents.i2s_opts[i] = I2S[i].p

    _handle_error(
        _libbluespy.bluespy_capture(
            filename.encode("utf-8"), opts,
        )
    )

    _libbluespy.bluespy_delete(opts)
    atexit.register(close_file)
    atexit.register(stop_capture)

def stop_capture():
    """! Stop the current capture

    @exception BluespyError: Exception in the bluespy library"""
    atexit.unregister(stop_capture)
    _handle_error(_libbluespy.bluespy_stop_capture())

def blueQ_connect_IUT_serial(port, baudrate=115200, HW_flow_control=False):
    """! Connect to an IUT for running blueQ tests

    @param port: String value of port to use
    @param baudrate: integer baudrate of port
    @param HW_flow_control: Enable/disable hardware flow control
    @exception BluespyError: Exception in the bluespy library"""
    _handle_error(_libbluespy.blueQ_connect_IUT_serial(port.encode("utf-8"),
                                                       baudrate,
                                                       0x2 if HW_flow_control else 0x0,
                                                       0x0,
                                                       0x0))
    #TODO: COM port disconnect

def blueQ_set_config(IXIT_file, ICS_file):
    _handle_error(_libbluespy.blueQ_set_config(IXIT_file.encode("utf-8"),ICS_file.encode("utf-8"), None))

def blueQ_run_test(TCID, print_progress=0):
    """! Run a single blueQ test

    @param TCID: The test to run, matching the format HCI/CCO/BI-79-C
    @param print_progress: Print status updates and errors to stdout"""
    ret = _libbluespy.blueQ_run_test(TCID.encode("utf-8"), print_progress)
    if ret.error.value:
        raise BluespyError(ret.error)

    return ret

def load_file(filename):
    """! Load an existing capture

    @exception BluespyError: Exception in the bluespy library"""
    _handle_error(_libbluespy.bluespy_load_file(filename.encode("utf-8")))
    atexit.register(close_file)

def close_file():
    """! Close an existing capture

    @exception BluespyError: Exception in the bluespy library"""
    atexit.unregister(close_file)
    _handle_error(_libbluespy.bluespy_close_file())

def get_device_id(addr):
    """! Get the Device ID from an address

    @param addr: Six bytes representing an address
    @return: Device ID. -1 = no device"""
    return _libbluespy.bluespy_get_device_id(addr)

def get_audiostreams(id_ = id(0xFFFFFFFFFFFFFFFF)):
    """! Get the ids of the audio streams from 'id'

    If id is device_id: Streams which a device is creating.
    If id is connection_id: Streams which are part of a connection.
    If id is BLUESPY_ID_INVALID: Streams not associated with any device, e.g. audiopod streams.

    @param id_: Device ID or Connection ID, or -1 for audiopod streams.
    @return: Array of audio stream IDs"""
    stream_id_span = _libbluespy.bluespy_get_audiostreams(id_)
    return [stream_id_span.data[i] for i in range(stream_id_span.size)]

class id(_ct.c_uint64):
    """!
    An object referencing a loaded event, device, connection, or audio stream.

    Do not make your own, only get these from the bluespy functions.
    After running close_file(), do not call any methods on any existing event_id objects.

    Any query (see the documentation or Help->Query List in the GUI) can be accessed as an attribute on this object
    """
    def __bool__(self):
        """! Returns true if this is a valid ID"""
        return self.value != 0xFFFFFFFFFFFFFFFF

    def query(self, name):
        """!
        Get a query from this object, and return it in its preferred form

        @param name: A query string, e.g. "summary"
        @return: A string, int or bool depending on the query"""
        s = _ct.c_char_p()
        i = _ct.c_int64()
        b = _ct.c_bool()
        r = _libbluespy.bluespy_query_auto(
            self.value, name.encode("utf-8"), _ct.byref(s), _ct.byref(i), _ct.byref(b)
        )
        if r == 1:
            return s.value.decode("utf-8")
        if r == 2:
            return i.value
        if r == 3:
            return b.value
        raise AttributeError()

    def __getattr__(self, name):
        """Access queries as attributes"""
        return self.query(name)

    def query_str(self, name):
        """!
        Get a query from this object, and return it as a string

        @param name: A query string, e.g. "summary"
        @return: string"""
        return _libbluespy.bluespy_query(self.value, name.encode("utf-8")).decode(
            "utf-8"
        )

    def query_int(self, name):
        """!
        Get a query from this object, and return it as an integer if possible

        @param name: A query string, e.g. "summary"
        @return: int"""
        return _libbluespy.bluespy_query_int(self.value, name.encode("utf-8"))

    def query_bool(self, name):
        """!
        Get a query from this object, and return it as a bool if possible

        @param name: A query string, e.g. "acked"
        @return: bool"""
        return _libbluespy.bluespy_query_bool(self.value, name.encode("utf-8"))

class event_id(id):
    """!
    An object referencing a loaded packet.

    Do not make your own, only get these from the 'packets' object.
    After running close_file(), do not call any methods on any existing event_id objects.

    Any query (see the documentation or Help->Query List in the GUI) can be accessed as an attribute on this object
    """

    def parent(self):
        """! Get the a higher layer packet that contains this one.
        e.g. if this is a baseband data packet get the L2CAP packet it is part of.

        @return: event_id"""
        return _libbluespy.bluespy_get_parent(self)

    def children(self):
        """! Get all constituent packets of this packet.
        e.g. if this is an L2CAP packet

        @return: List of event_ids"""
        count = _ct.c_uint32()
        c = _libbluespy.bluespy_get_children(self, _ct.byref(count))
        return (
            list(_ct.cast(c, _ct.POINTER(event_id * count.value)).contents)
            if count.value > 0
            else []
        )

class device_id(id):
    """!
    An object referencing a device.

    Do not make your own, only get these from the device id functions.
    Device IDs are ordered arbitrarily
    After running close_file(), do not call any methods on any existing device_id objects.
    """
    def get_connections(self):
        """! Get the connections
        @return: Array of connection IDs"""
        conn_id_span = _libbluespy.bluespy_get_connections(self)
        return [conn_id_span.data[i] for i in range(conn_id_span.size)]

    def get_audio_streams(self):
        """! Get the audio streams
        @return: Array of audio streams IDs"""
        stream_id_span = _libbluespy.bluespy_get_audiostreams(self)
        return [stream_id_span.data[i] for i in range(stream_id_span.size)]

class connection_id(id):
    """!
    An object referencing a connection.

    Do not make your own, only get these from the connection id functions.
    Connection IDs are ordered arbitrarily
    After running close_file(), do not call any methods on any existing connection_id objects.
    """
    def get_audio_streams(self):
        """! Get the audio streams
        @return: Array of audio streams IDs"""
        stream_id_span = _libbluespy.bluespy_get_audiostreams(self)
        return [stream_id_span.data[i] for i in range(stream_id_span.size)]

class audiostream_id(id):
    """!
    An object referencing a audio stream.

    Do not make your own, only get these from the audio stream id functions.
    Audio Stream IDs are ordered arbitrarily
    After running close_file(), do not call any methods on any existing audiostream_id objects.
    """

class Packets(object):
    """List-like object representing the currently loaded baseband packets."""

    def __len__(self):
        """Current number of baseband packets captured"""
        return _libbluespy.bluespy_packet_count()

    def __getitem__(self, i):
        """!
        Get an event_id for a packet

        @param i: Index of packet, 0 <= i < __len__()
        @return: An event_id
        """
        i = int(i)
        if i < 0 or i >= _libbluespy.bluespy_packet_count():
            raise IndexError()
        return _libbluespy.bluespy_get_baseband(i)

packets = Packets()

class Devices:
    def __iter__(self):
        return DevicesIter()

class DevicesIter:
    def __init__(self):
        self.current = device_id(-1)
    def __next__(self):
        self.current = _libbluespy.bluespy_get_next_device_id(self.current)
        if not self.current:
            raise StopIteration
        return self.current

devices = Devices()

class Connections:
    def __iter__(self):
        return ConnectionsIter()

class ConnectionsIter:
    def __init__(self):
        self.current = connection_id(-1)
    def __next__(self):
        self.current = _libbluespy.bluespy_get_next_connection_id(self.current)
        if not self.current:
            raise StopIteration
        return self.current

connections = Connections()

class Audiostreams:
    def __iter__(self):
        return AudiostreamsIter()

class AudiostreamsIter:
    def __init__(self):
        self.current = audiostream_id(-1)
    def __next__(self):
        self.current = _libbluespy.bluespy_get_next_audiostream_id(self.current)
        if not self.current:
            raise StopIteration
        return self.current

audiostreams = Audiostreams()
def create_filter_file(filename, range_start = -1, keep_spec = True, keep_logic = True, keep_uart = True, keep_i2s_and_audiopod = True):
    """! Creates a filter file

    @param filename: File name
    @param range_start: File name
    @param keep_spec: Enable copying spectrum
    @param keep_logic: Enable copying logic
    @param keep_uart: Enable copying UART
    @param keep_i2s_and_audiopod: Enable copying I2S and Audiopod

    @return: file_id of filter file. -1 = invalid"""
    opts = _libbluespy.bluespy_filter_file_options_alloc()
    opts.contents.range_start = range_start
    opts.contents.keep_spectrum = keep_spec
    opts.contents.keep_logic = keep_logic
    opts.contents.keep_uart = keep_uart
    opts.contents.keep_i2s_and_audiopod = keep_i2s_and_audiopod

    id_ = _libbluespy.bluespy_create_filter_file(filename.encode("utf-8"), opts)
    _libbluespy.bluespy_filter_file_options_delete(opts)
    return id_

def add_to_filter_file(file_, event_):
    """! Add an event to a filter file

    @param file_: File ID
    @param event_: Event ID

    @exception BluespyError: Exception in the bluespy library"""
    _handle_error(_libbluespy.bluespy_add_to_filter_file(file_, event_))

def close_filter_file(file_):
    """! Close a filter file

    @param file_: File ID

    @exception BluespyError: Exception in the bluespy library"""
    _handle_error(_libbluespy.bluespy_close_filter_file(file_))

def get_logic_at_time(ts):
    """! Get the logic state at ts

    @param ts: Timestamp

    @return: 32 bit integer. The i'th bit represents the state of the i'th logic line"""
    return _libbluespy.bluespy_get_logic_at_time(ts)

def get_next_logic_change(ts,  mask):
    """! Get the next logic state after ts

    @param ts: Timestamp
    @param mask: 32 integer mask. logic lines corresponding to zero bits are ignored

    @return: A struct containing a 32 integer mask representing the next logic state, and the time of transition"""

    return _libbluespy.bluespy_get_next_logic_change(ts,  mask)

def wait_until_next_logic_change(mask, timeout, ts):
    """! Waits until a logic line in the specified mask changes or until the given timeout period passes

    @param mask: 32 integer mask. logic lines corresponding to zero bits are ignored
    @param timeout: Timeout
    @param ts: Time to wait from

    @return: A struct containing the new state, the line which switched, the time of the switch, and whether the logic state changed or the function timed out. True = Logic changed. False = Timeout"""

    return _libbluespy.bluespy_wait_until_next_logic_change(mask, timeout, ts)

def add_link_key(key, addr0=0, addr1=0):
    """! Add a link key for decryption

    @param key: Link key as a 16-byte bytes object
    @param addr0: (Optional) MAC address of central as a 64-bit integer
    @param addr1: (Optional) MAC address of peripheral as a 64-bit integer
    """
    _handle_error(_libbluespy.bluespy_add_link_key(key, addr0, addr1))

class file_id(_ct.c_uint64):
    """!
    An object referencing a loaded file.

    Do not make your own, only get these from the 'files' object.
    """

    def __bool__(self):
        """! Returns true if this is a valid packet"""
        return self.value != 0xFFFFFFFFFFFFFFFF

    def __str__(self):
        """! Returns root filename"""
        return _libbluespy.bluespy_get_filter_file_name(self).decode("utf-8")

def start_gui():
    """! Spawn an instance of the user interface"""
    _libbluespy.bluespy_start_gui()

class _multi_moreph_options(_ct.Structure):
    _fields_ = [
        ("enable_CL", _ct.c_bool),
        ("enable_LE", _ct.c_bool),
        ("enable_wifi", _ct.c_bool),
    ]
def measure_latency(channel0, channel1, include_pres_delay, ts):
    """! Measures the latency between two audio streams

    @param channel0: Audio channel 0
    @param channel1: Audio channel 1
    @param include_pres_delay: Include presentation delay
    @param ts: Timestamp

    @return Array of latency results
    """
    res_data = _libbluespy.bluespy_measure_latency(channel0,channel1,include_pres_delay,ts)
    return res_data

def set_cis_lc3_config(
        audio_id,
        codec_frames_per_SDU=1,
        presentation_delay_us = 40000,
        octets_per_codec_frame = 120,
        frame_duration_us = 10000,
        sampling_frequency_Hz = 48000,
        audio_channel_allocation = 0x100
        ):
    """! Set the config of a CIS stream

    @param audio_id: CIS stream ID
    @param codec_frames_per_SDU: Codec Frames per SDU
    @param presentation_delay_us: Presentation Delay in us
    @param octets_per_codec_frame: Octets per Codec Frame
    @param frame_duration_us: Frame Duration in us
    @param sampling_frequency_Hz: Sample Rate in Hz
    @param audio_channel_allocation: Audio Channel Allocation mask
    @return: Array of serial numbers"""
    conf = _cis_lc3_config()
    conf.codec_frames_per_SDU = codec_frames_per_SDU
    conf.presentation_delay_us = presentation_delay_us
    conf.octets_per_codec_frame = octets_per_codec_frame
    conf.frame_duration_us = frame_duration_us
    conf.sampling_frequency_Hz = sampling_frequency_Hz
    conf.audio_channel_allocation = audio_channel_allocation
    _handle_error(
        _libbluespy.bluespy_set_cis_lc3_config(audio_id, _ct.byref(conf))
    )

def play_to_audiopod_output(filename, loop = False):
    """! Playback audio file to audiopod

    @param filename: Audio file
    @param loop: Loop audio"""
    _handle_error(
        _libbluespy.bluespy_play_to_audiopod_output(filename.encode("utf-8"), loop)
    )

def stop_audio():
    """! Stop file in playback"""
    _handle_error(
        _libbluespy.bluespy_stop_audio()
    )
class _capture_audiopod_options(_ct.Structure):
    _fields_ = [
        # Valid sample rates in Hz are:
        # 8'000, 11'025, 16'000, 22'050, 32'000, 44'100, 48'000, 88'200, 96'000, 176'400, 192'000
        ("sample_rate", _ct.c_uint32),
        ("channels", audio_channel),
        ("output", audio_connect),
        ("input", audio_connect),
        ("bias", audio_bias),
        ("current_probe", _ct.c_bool),
        ("LA_low_voltage", _ct.c_double),
        ("LA_high_voltage", _ct.c_double),
        ("power_supply_V", _ct.c_double),
        ("VIO_dV", _ct.c_double),
        ("AGC", _ct.c_bool),
        ("DRC", _ct.c_bool),
        ("second_I2S_input", _ct.c_bool),
        ("vol_in_left", _ct.c_double),
        ("vol_in_right", _ct.c_double),
        ("vol_out_left", _ct.c_double),
        ("vol_out_right", _ct.c_double),
    ]

class _capture_i2s_options(_ct.Structure):
    _fields_ = [
        ("SCLK_line", _ct.c_uint8),
        ("WS_line", _ct.c_uint8),
        ("SD_line", _ct.c_uint8),
        ("n_channels", _ct.c_uint8),
        ("bits_per_ch", _ct.c_uint8),
        ("sample_on_rising_edge", _ct.c_bool),
        ("first_chan_follows_WS_high", _ct.c_bool),
        ("one_sample_delay", _ct.c_bool),
        ("MSB_first", _ct.c_bool),
        ("DSP_mode", _ct.c_bool),
        ("master", _ct.c_bool),
    ]

class _capture_options(_ct.Structure):
    _fields_ = [
        ("enable_CL", _ct.c_bool),
        ("enable_LE", _ct.c_bool),
        ("enable_QHS", _ct.c_bool),
        ("enable_15_4", _ct.c_bool),
        ("enable_wifi", _ct.c_bool),
        ("enable_MHDT_CL", _ct.c_bool),
        ("enable_MHDT_LE", _ct.c_bool),
        ("enable_Dukosi", _ct.c_bool),
        ("enable_Varjo", _ct.c_bool),
        ("enable_Channel_Sounding", _ct.c_bool),
        ("enable_HDT", _ct.c_bool),
        # Valid spectrum periods in microseconds are:
        # 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000
        # 0 to disable spectrum
        ("spectrum_period", _ct.c_uint16),
        ("logic_mask", _ct.c_uint32),
        ("logic_use_external_vref", _ct.c_bool),
        ("logic_rate", logic_rate),
        # multi_moreph_opts points to an array of N-1 option structs.
        # N being the number of devices connected.
        ("multi_moreph_opts", _multi_moreph_options * 32),
        ("audiopod_opts", _ct.POINTER(_capture_audiopod_options)),
        ("i2s_opts", _ct.POINTER(_capture_i2s_options) * 2),
    ]

class _filter_file_options(_ct.Structure):
    _fields_ = [
        ("range_start", _ct.c_uint64),
        ("keep_spectrum", _ct.c_bool),
        ("keep_logic", _ct.c_bool),
        ("keep_uart", _ct.c_bool),
        ("keep_i2s_and_audiopod", _ct.c_bool),
    ]

class _logic_change(_ct.Structure):
    _fields_ = [
        ("state", _ct.c_uint32),
        ("change_mask", _ct.c_uint32),
        ("time", time_point),
    ]

class _connection_id_span(_ct.Structure):
    _fields_ = [
        ("data", _ct.POINTER(connection_id)),
        ("size", _ct.c_uint64),
    ]

class _audiostream_id_span(_ct.Structure):
    _fields_ = [
        ("data", _ct.POINTER(audiostream_id)),
        ("size", _ct.c_uint64),
    ]

class latency_status(_ct.c_int):
    """! Return log level"""
    def __str__(self):

        return _libbluespy.bluespy_latency_status_string(self.value).decode("utf-8")

    def __repr__(self):
        return "{}: {}".format(self.value, self.__str__()) if self.value else ""

    def __bool__(self):
        return self.value == 0

class _latency_result(_ct.Structure):
    _fields_ = [
        ("time_difference_ns", _ct.c_int64),
        ("time_difference_min_ns", _ct.c_int64),
        ("time_difference_max_ns", _ct.c_int64),
        ("measurement_time", time_point),
        ("status", latency_status),
        ("total_energy", _ct.c_double),
        ("peak_ratio", _ct.c_double),
        ("three_measurements_expected", _ct.c_bool),
    ]

    def __repr__(self):
        return "[\n\ttime_difference: min:{}, avg:{}, max:{},\n\ttime:{}, status:{}, total_energy:{:.3%}, peak_ratio:{:.3%}, 3 measures expected:{}\n]".format( self.time_difference_min_ns, self.time_difference_ns, self.time_difference_max_ns, self.measurement_time, self.status, self.total_energy, self.peak_ratio, self.three_measurements_expected)

class _audio_channel_t(_ct.Structure):
    _fields_ = [
        ("ID", audiostream_id),
        ("channel_index", _ct.c_uint8),
    ]

class _cis_lc3_config(_ct.Structure):
    _fields_ = [
        ("codec_frames_per_SDU", _ct.c_uint64),
        ("presentation_delay_us", _ct.c_uint64),
        ("octets_per_codec_frame", _ct.c_uint32),
        ("frame_duration_us", _ct.c_uint32),
        ("sampling_frequency_Hz", _ct.c_uint32),
        ("audio_channel_allocation", _ct.c_uint32),
    ]

class _blueQ_IUT_serial_options(_ct.Structure):
    _fields_ = [
        ("baudrate", _ct.c_uint32),
        ("HW_flow_control", _ct.c_uint8),
        ("port", _ct.c_char_p),
    ]

class _blueQ_config_options(_ct.Structure):
    _fields_ = [
        ("IXIT_file", _ct.c_char_p),
        ("ICS_file", _ct.c_char_p)
    ]

class _blueQ_result_data(_ct.Structure):
    _fields_ = [
        ("start_ts", time_point),
        ("end_ts", time_point),
        ("error", error),
        ("verdict", blueQ_testcase_verdict),
    ]

    def __str__(self):
        """! Summary of result"""
        if not self.error:
            return 'blueQ test execution failure: {}, {} - {}'.format(self.error, self.start_ts, self.end_ts)

        return 'blueQ result: {}, {} - {}'.format(self.verdict, self.start_ts, self.end_ts)

_libbluespy.bluespy_error_string.argtypes = [error]
_libbluespy.bluespy_error_string.restype = _ct.c_char_p

_libbluespy.blueQ_testcase_verdict_string.argtypes = [_ct.c_uint32]
_libbluespy.blueQ_testcase_verdict_string.restype = _ct.c_char_p

_libbluespy.bluespy_connect.argtypes = [_ct.c_uint32]
_libbluespy.bluespy_connect.restype = error

_libbluespy.blueQ_connect.argtypes = [_ct.c_uint32]
_libbluespy.blueQ_connect.restype = error

_libbluespy.bluespy_connect_multiple.argtypes = [_ct.POINTER(_ct.c_uint32), _ct.c_uint64]
_libbluespy.bluespy_connect_multiple.restype = error

_libbluespy.bluespy_morephs_connected.argtypes = [_ct.POINTER(_ct.POINTER(_ct.c_uint32))]
_libbluespy.bluespy_morephs_connected.restype = _ct.c_uint64

_libbluespy.bluespy_disconnect.argtypes = []
_libbluespy.bluespy_disconnect.restype = error

_libbluespy.bluespy_moreph_reboot.argtypes = [_ct.c_uint32]
_libbluespy.bluespy_moreph_reboot.restype = error

_libbluespy.bluespy_print_time.argtypes = [time_point]
_libbluespy.bluespy_print_time.restype = _ct.c_char_p

_libbluespy.bluespy_add_log_message.argtypes = [log_level, _ct.c_char_p, time_point]
_libbluespy.bluespy_add_log_message.restype = error

_libbluespy.blueQ_set_config.argtypes = [_ct.c_char_p, _ct.c_char_p, _ct.c_void_p]
_libbluespy.blueQ_set_config.restype = error

_libbluespy.blueQ_connect_IUT_serial.argtypes = [_ct.c_char_p,
                                                 _ct.c_uint32,
                                                 blueQ_serial_flow_control,
                                                 blueQ_serial_parity_bits,
                                                 blueQ_serial_stop_bits]
_libbluespy.blueQ_connect_IUT_serial.restype = error

_libbluespy.blueQ_run_test.argtypes = [_ct.c_char_p, blueQ_verbosity]
_libbluespy.blueQ_run_test.restype = _blueQ_result_data

_libbluespy.bluespy_capture_options_alloc.argtypes = []
_libbluespy.bluespy_capture_options_alloc.restype = _ct.POINTER(_capture_options)

_libbluespy.bluespy_capture_audiopod_options_alloc.argtypes = []
_libbluespy.bluespy_capture_audiopod_options_alloc.restype = _ct.POINTER(_capture_audiopod_options)

_libbluespy.bluespy_capture_i2s_options_alloc.argtypes = []
_libbluespy.bluespy_capture_i2s_options_alloc.restype = _ct.POINTER(_capture_i2s_options)

_libbluespy.bluespy_delete.argtypes = [_ct.c_void_p]
_libbluespy.bluespy_delete.restype = None

_libbluespy.bluespy_capture.argtypes = [
    _ct.c_char_p, _ct.POINTER(_capture_options)]
_libbluespy.bluespy_capture.restype = error

_libbluespy.bluespy_stop_capture.argtypes = []
_libbluespy.bluespy_stop_capture.restype = error

_libbluespy.bluespy_load_file.argtypes = [_ct.c_char_p]
_libbluespy.bluespy_load_file.restype = error

_libbluespy.bluespy_close_file.argtypes = []
_libbluespy.bluespy_close_file.restype = error

_libbluespy.bluespy_packet_count.argtypes = []
_libbluespy.bluespy_packet_count.restype = _ct.c_uint32

_libbluespy.bluespy_get_baseband.argtypes = [_ct.c_uint32]
_libbluespy.bluespy_get_baseband.restype = event_id

_libbluespy.bluespy_get_parent.argtypes = [event_id]
_libbluespy.bluespy_get_parent.restype = event_id

_c_uint32_p = _ct.POINTER(_ct.c_uint32)
_libbluespy.bluespy_get_children.argtypes = [event_id, _c_uint32_p]
_libbluespy.bluespy_get_children.restype = _ct.POINTER(event_id)

_libbluespy.bluespy_query.argtypes = [id, _ct.c_char_p]
_libbluespy.bluespy_query.restype = _ct.c_char_p

_libbluespy.bluespy_query_int.argtypes = [id, _ct.c_char_p]
_libbluespy.bluespy_query_int.restype = _ct.c_int64

_libbluespy.bluespy_query_bool.argtypes = [id, _ct.c_char_p]
_libbluespy.bluespy_query_bool.restype = _ct.c_bool

_libbluespy.bluespy_query_auto.argtypes = [
    id,
    _ct.c_char_p,
    _ct.POINTER(_ct.c_char_p),
    _ct.POINTER(_ct.c_int64),
    _ct.POINTER(_ct.c_bool),
]
_libbluespy.bluespy_query_auto.restype = _ct.c_int

_libbluespy.bluespy_add_link_key.argtypes = [
    _ct.c_char_p, _ct.c_uint64, _ct.c_uint64]
_libbluespy.bluespy_add_link_key.restype = error

_libbluespy.bluespy_get_filter_file_name.argtypes = [file_id]
_libbluespy.bluespy_get_filter_file_name.restype = _ct.c_char_p

_libbluespy.bluespy_filter_file_options_alloc.argtypes = []
_libbluespy.bluespy_filter_file_options_alloc.restype =  _ct.POINTER( _filter_file_options)

_libbluespy.bluespy_filter_file_options_delete.argtypes = [_ct.POINTER( _filter_file_options)]
_libbluespy.bluespy_filter_file_options_delete.restype =  None

_libbluespy.bluespy_create_filter_file.argtypes = [_ct.c_char_p, _ct.POINTER( _filter_file_options)]
_libbluespy.bluespy_create_filter_file.restype = file_id

_libbluespy.bluespy_add_to_filter_file.argtypes = [file_id, event_id]
_libbluespy.bluespy_add_to_filter_file.restype = error

_libbluespy.bluespy_close_filter_file.argtypes = [file_id]
_libbluespy.bluespy_close_filter_file.restype = error

_libbluespy.bluespy_get_logic_at_time.argtypes = [time_point]
_libbluespy.bluespy_get_logic_at_time.restype = _ct.c_uint32

_libbluespy.bluespy_get_next_logic_change.argtypes = [time_point, _ct.c_uint32]
_libbluespy.bluespy_get_next_logic_change.restype = _logic_change

_libbluespy.bluespy_wait_until_next_logic_change.argtypes = [_ct.c_uint32, time_point, time_point]
_libbluespy.bluespy_wait_until_next_logic_change.restype = _logic_change

_libbluespy.bluespy_start_gui.argtypes = []
_libbluespy.bluespy_start_gui.restype = None

_libbluespy.bluespy_init.argtypes = []
_libbluespy.bluespy_init.restype = None

_libbluespy.bluespy_deinit.argtypes = []
_libbluespy.bluespy_deinit.restype = None

_libbluespy.bluespy_get_device_id.argtypes = [_ct.c_char_p]
_libbluespy.bluespy_get_device_id.restype = device_id

_libbluespy.bluespy_get_next_device_id.argtypes = [device_id]
_libbluespy.bluespy_get_next_device_id.restype = device_id

_libbluespy.bluespy_get_next_connection_id.argtypes = [connection_id]
_libbluespy.bluespy_get_next_connection_id.restype = connection_id

_libbluespy.bluespy_get_next_audiostream_id.argtypes = [audiostream_id]
_libbluespy.bluespy_get_next_audiostream_id.restype = audiostream_id

_libbluespy.bluespy_get_connections.argtypes = [device_id]
_libbluespy.bluespy_get_connections.restype = _connection_id_span

_libbluespy.bluespy_get_audiostreams.argtypes = [id]
_libbluespy.bluespy_get_audiostreams.restype = _audiostream_id_span

_libbluespy.bluespy_latency_status_string.argtypes = [latency_status]
_libbluespy.bluespy_latency_status_string.restype = _ct.c_char_p

_libbluespy.bluespy_measure_latency.argtypes = [_audio_channel_t,_audio_channel_t, _ct.c_bool, time_point]
_libbluespy.bluespy_measure_latency.restype = _latency_result

_libbluespy.bluespy_set_cis_lc3_config.argtypes = [audiostream_id, _ct.POINTER(_cis_lc3_config)]
_libbluespy.bluespy_set_cis_lc3_config.restype = error

_libbluespy.bluespy_play_to_audiopod_output.argtypes = [_ct.c_char_p,_ct.c_bool]
_libbluespy.bluespy_play_to_audiopod_output.restype = error

_libbluespy.bluespy_stop_audio.argtypes = []
_libbluespy.bluespy_stop_audio.restype = error

_libbluespy.bluespy_init()
atexit.register(_libbluespy.bluespy_deinit)
