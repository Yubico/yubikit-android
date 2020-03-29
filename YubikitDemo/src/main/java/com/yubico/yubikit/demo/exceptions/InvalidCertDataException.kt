package com.yubico.yubikit.demo.exceptions

import com.yubico.yubikit.apdu.ApduException

class InvalidCertDataException(message: String, cause: Throwable?) : ApduException(message, cause) {
    constructor(message: String) : this(message, null)
}