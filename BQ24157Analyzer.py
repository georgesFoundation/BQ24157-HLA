from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, NumberSetting


BQ24157_DEFAULT_ADDRESS = 0x6A

REGISTERS = {
    0x00: "Status",
    0x01: "Control",
    0x02: "BatteryVoltage",
    0x03: "Revision",
    0x04: "ChargerCurrent",
    0x05: "SpecialChargerVoltage",
    0x06: "SafetyLimit",
}

CHARGE_STATES = {
    0b00: "Ready",
    0b01: "ChargeInProgress",
    0b10: "ChargeDone",
    0b11: "Fault",
}

CHARGE_FAULTS = {
    0b000: "Normal",
    0b001: "VBUS_OVP",
    0b010: "SleepMode",
    0b011: "BadAdaptorOrVbusLow",
    0b100: "OutputOVP",
    0b101: "ThermalShutdown",
    0b110: "TimerFault",
    0b111: "NoBattery",
}

BOOST_FAULTS = {
    0b000: "Normal",
    0b001: "VBUS_OVP",
    0b010: "Overload",
    0b011: "BatteryLow",
    0b100: "BatteryOVP",
    0b101: "ThermalShutdown",
    0b110: "TimerFault",
    0b111: "Reserved",
}

INPUT_LIMITS = {
    0b00: "100 mA",
    0b01: "500 mA",
    0b10: "800 mA",
    0b11: "No input limit",
}

PART_NUMBERS = {
    0b10: "BQ24157",
}


def reg_name(register):
    return REGISTERS.get(register, "Reg0x%02X" % register)


def bit_value(value, bit_num):
    return bool(value & (1 << bit_num))


def field(value, hi, lo):
    mask = (1 << (hi - lo + 1)) - 1
    return (value >> lo) & mask


def bytes_hex(data):
    return " ".join("0x%02X" % byte for byte in data)


def on_off(value):
    return "1" if value else "0"


def decode_status(value):
    fault = field(value, 2, 0)
    boost = bit_value(value, 3)
    state = field(value, 5, 4)
    fault_name = BOOST_FAULTS[fault] if boost else CHARGE_FAULTS[fault]
    return (
        "0x%02X stat=%s fault=%s mode=%s EN_STAT=%s RESET_TMR=%s"
        % (
            value,
            CHARGE_STATES[state],
            fault_name,
            "boost" if boost else "charge",
            on_off(bit_value(value, 6)),
            on_off(bit_value(value, 7)),
        )
    )


def decode_control(value):
    v_low_code = field(value, 5, 4)
    i_lim_code = field(value, 7, 6)
    return (
        "0x%02X mode=%s hi_z=%s charge=%s term=%s weak_bat=%d mV input_limit=%s"
        % (
            value,
            "boost" if bit_value(value, 0) else "charger",
            on_off(bit_value(value, 1)),
            "disabled" if bit_value(value, 2) else "enabled",
            "enabled" if bit_value(value, 3) else "disabled",
            3400 + 100 * v_low_code,
            INPUT_LIMITS[i_lim_code],
        )
    )


def decode_battery_voltage(value):
    bat_vreg_code = field(value, 7, 2)
    return (
        "0x%02X otg_en=%s otg_pl=%s bat_vreg=%d mV"
        % (
            value,
            on_off(bit_value(value, 0)),
            "high" if bit_value(value, 1) else "low",
            3500 + 20 * bat_vreg_code,
        )
    )


def decode_revision(value):
    rev = field(value, 2, 0)
    pn = field(value, 4, 3)
    vendor = field(value, 7, 5)
    return "0x%02X rev=%d pn=%s vendor=%d" % (
        value,
        rev,
        PART_NUMBERS.get(pn, "0b%s" % format(pn, "02b")),
        vendor,
    )


def decode_charger_current(value):
    iterm_code = field(value, 2, 0)
    ichg_code = field(value, 6, 3)
    return (
        "0x%02X iterm_code=%d charge_current_code=%d reset=%s"
        % (
            value,
            iterm_code,
            ichg_code,
            on_off(bit_value(value, 7)),
        )
    )


def decode_special_charger_voltage(value):
    vsreg_code = field(value, 2, 0)
    return (
        "0x%02X vsreg=%d mV cd_stat=%s dpm_stat=%s low_chg=%s"
        % (
            value,
            4200 + 80 * vsreg_code,
            on_off(bit_value(value, 3)),
            on_off(bit_value(value, 4)),
            on_off(bit_value(value, 5)),
        )
    )


def decode_safety_limit(value):
    vr_max_code = field(value, 3, 0)
    current_code = field(value, 7, 4)
    return (
        "0x%02X vr_max=%d mV current_sense_limit_code=%d"
        % (
            value,
            4200 + 20 * vr_max_code,
            current_code,
        )
    )


def format_value(register, value):
    if register == 0x00:
        return decode_status(value)
    if register == 0x01:
        return decode_control(value)
    if register == 0x02:
        return decode_battery_voltage(value)
    if register == 0x03:
        return decode_revision(value)
    if register == 0x04:
        return decode_charger_current(value)
    if register == 0x05:
        return decode_special_charger_voltage(value)
    if register == 0x06:
        return decode_safety_limit(value)
    return "0x%02X" % value


class BQ24157Analyzer(HighLevelAnalyzer):
    i2c_address = NumberSetting(min_value=0, max_value=0x7F)

    result_types = {
        "read": {"format": "{{data.summary}}"},
        "write": {"format": "{{data.summary}}"},
        "select": {"format": "{{data.summary}}"},
        "error": {"format": "{{data.summary}}"},
    }

    def __init__(self):
        self._address = int(self.i2c_address)
        if self._address == 0:
            self._address = BQ24157_DEFAULT_ADDRESS
        self._reset_transaction()

    def _reset_transaction(self):
        self._transaction_start = None
        self._segments = []
        self._current_segment = None

    def decode(self, frame):
        if frame.type == "start":
            if self._transaction_start is None:
                self._transaction_start = frame.start_time
            return None

        if frame.type == "address":
            if self._transaction_start is None:
                self._transaction_start = frame.start_time

            address = self._value_byte(frame.data.get("address"))
            read = bool(frame.data.get("read", False))
            self._current_segment = {"address": address, "read": read, "data": []}
            self._segments.append(self._current_segment)
            return None

        if frame.type == "data":
            if self._current_segment is not None:
                self._current_segment["data"].append(self._value_byte(frame.data.get("data")))
            return None

        if frame.type == "stop":
            result = self._decode_transaction(frame.end_time)
            self._reset_transaction()
            return result

        return None

    def _value_byte(self, value):
        if isinstance(value, (bytes, bytearray, list, tuple)):
            return int(value[0])
        return int(value)

    def _decode_transaction(self, end_time):
        segments = [segment for segment in self._segments if segment["address"] == self._address]
        if not segments:
            return None

        start_time = self._transaction_start
        if start_time is None:
            start_time = end_time

        if len(segments) == 1:
            return self._decode_single_segment(segments[0], start_time, end_time)

        if len(segments) == 2 and not segments[0]["read"] and segments[1]["read"]:
            return self._decode_write_read(segments[0], segments[1], start_time, end_time)

        summary = "BQ24157 unsupported transaction: " + self._segments_summary(segments)
        return AnalyzerFrame("error", start_time, end_time, {"summary": summary})

    def _decode_single_segment(self, segment, start_time, end_time):
        data = segment["data"]
        if segment["read"]:
            summary = "BQ24157 read without register pointer: %s" % bytes_hex(data)
            return AnalyzerFrame("error", start_time, end_time, {"summary": summary})

        if len(data) == 1:
            summary = "BQ24157 select %s (0x%02X)" % (reg_name(data[0]), data[0])
            return AnalyzerFrame("select", start_time, end_time, {"summary": summary})

        register = data[0]
        payload = data[1:]

        if len(payload) == 1:
            value = payload[0]
            summary = "BQ24157 write %s (0x%02X) = %s" % (
                reg_name(register),
                register,
                format_value(register, value),
            )
            return AnalyzerFrame("write", start_time, end_time, {"summary": summary})

        summary = "BQ24157 write %s (0x%02X) = %s" % (reg_name(register), register, bytes_hex(payload))
        return AnalyzerFrame("write", start_time, end_time, {"summary": summary})

    def _decode_write_read(self, write_segment, read_segment, start_time, end_time):
        pointer = write_segment["data"]
        data = read_segment["data"]

        if len(pointer) != 1:
            summary = "BQ24157 read with unexpected pointer bytes: %s -> %s" % (
                bytes_hex(pointer),
                bytes_hex(data),
            )
            return AnalyzerFrame("error", start_time, end_time, {"summary": summary})

        register = pointer[0]
        if len(data) == 1:
            value = data[0]
            summary = "BQ24157 read %s (0x%02X) = %s" % (
                reg_name(register),
                register,
                format_value(register, value),
            )
            return AnalyzerFrame("read", start_time, end_time, {"summary": summary})

        summary = "BQ24157 read %s (0x%02X) = %s" % (reg_name(register), register, bytes_hex(data))
        return AnalyzerFrame("read", start_time, end_time, {"summary": summary})

    def _segments_summary(self, segments):
        parts = []
        for segment in segments:
            direction = "R" if segment["read"] else "W"
            parts.append("%s %s" % (direction, bytes_hex(segment["data"])))
        return "; ".join(parts)
