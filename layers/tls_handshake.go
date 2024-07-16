// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/gopacket"
)

// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

type HandshakeType uint8

// TLSHandshakeType known values.
const (
	TLSHANDSHAKE_HELLO_REQUEST       HandshakeType = 0x00
	TLSHANDSHAKE_CLIENT_HELLO        HandshakeType = 0x01
	TLSHANDSHAKE_SERVER_HELLO        HandshakeType = 0x02
	TLSHANDSHAKE_NEW_SESSION_TICKET  HandshakeType = 0x04
	TLSHANDSHAKE_ENCRYPTED_EXTENSION HandshakeType = 0x08
	TLSHANDSHAKE_CERTIFICATE         HandshakeType = 0x0b
	TLSHANDSHAKE_SERVER_KEY_EXCHANGE HandshakeType = 0x0c
	TLSHANDSHAKE_CERTIFICATE_REQUEST HandshakeType = 0x0d
	TLSHANDSHAKE_SERVER_DONE         HandshakeType = 0x0e
	TLSHANDSHAKE_CERTIFICATE_VERIFY  HandshakeType = 0x0f
	TLSHAKDSHAKE_CLIENT_KEY_EXCHANGE HandshakeType = 0x10
	TLSHANDSHAKE_FINISHED            HandshakeType = 0x14
	TLSHANDSHAKE_ALERT               HandshakeType = 0x15
)

// Strings shows the TLS handshake type nicely formatted
func (ht HandshakeType) String() string {
	switch ht {
	default:
		return "Unknown"
	case 0x01:
		return "Client_Hello"
	case 0x02:
		return "Server_Hello"
	case 0x04:
		return "New_Session_Ticket"
	case 0x08:
		return "Encrypted Extension"
	case 0x0b:
		return "Certificate"
	case 0x0c:
		return "Server Key Exchange"
	case 0x0d:
		return "Certificate Request"
	case 0x0e:
		return "Server Done"
	case 0x0f:
		return "Certificate Verify"
	case 0x10:
		return "Client Key Exchange"
	case 0x14:
		return "Finished"
	case 0x15:
		return "Alert"
	}
}

// TLSHandshakeRecord defines the structure of a Handshake Record
type TLSHandshakeRecord struct {
	TLSRecordHeader
	HandshakeType   HandshakeType
	ClientHello     ClientHello
	ServerHello     ServerHello
	ServerExtension EncryptedExtension
	Finished        Finished
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSHandshakeRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	t.HandshakeType = HandshakeType(data[0])
	switch t.HandshakeType {
	case TLSHANDSHAKE_CLIENT_HELLO:
		client := &ClientHello{}
		err := client.decodeFromBytes(data, nil)
		if err != nil {
			return err
		}
		t.ClientHello = *client

	case TLSHANDSHAKE_SERVER_HELLO:
		server := &ServerHello{}
		err := server.decodeFromBytes(data, nil)
		if err != nil {
			return err
		}
		t.ServerHello = *server
	case TLSHANDSHAKE_CERTIFICATE:

	case TLSHANDSHAKE_FINISHED:

	case TLSHANDSHAKE_ENCRYPTED_EXTENSION:
		extension := &EncryptedExtension{}
		err := extension.decodeFromBytes(data, nil)
		if err != nil {
			return err
		}
		t.ServerExtension = *extension
	}

	return nil
}

const (
	SNINameTypeDNS       uint8 = 0
	OCSPStatusRequest    uint8 = 1
	ClientHelloRandomLen       = 32
)

var (
	ErrHandshakeWrongType    = errors.New("handshake is of wrong type, or not a handshake message")
	ErrHandshakeBadLength    = errors.New("handshake has a malformed length")
	ErrHandshakeExtBadLength = errors.New("handshake extension has a malformed length")
)

type ClientHello struct {
	HandshakeType    uint8
	HandshakeLen     uint32
	HandshakeVersion TLSVersion
	SupportVersion   []TLSVersion
	Random           []byte
	SessionIDLen     uint32
	SessionID        []byte
	CipherSuiteLen   uint16
	CipherSuites     []CipherSuite
	CompressMethods  []uint8
	ExtensionLen     uint16
	Extensions       map[Extension]uint16 // [Type]Length
	SNI              string
	SignatureAlgs    []uint16
	SupportedGroups  []uint16
	SupportedPoints  []uint8
	OSCP             bool
	ALPNs            []string
}

func (ch ClientHello) String() string {
	str := fmt.Sprintln("Handshake Type:", ch.HandshakeType)
	str += fmt.Sprintln("Handshake Version:", ch.HandshakeVersion)
	str += fmt.Sprintf("SessionID: %#v\n", ch.SessionID)
	str += fmt.Sprintf("Cipher Suites (%d): %v\n", ch.CipherSuiteLen, ch.CipherSuites)
	str += fmt.Sprintf("Compression Methods: %v\n", ch.CompressMethods)
	str += fmt.Sprintln("Extensions:", ch.Extensions)
	str += fmt.Sprintf("SNI: %q\n", ch.SNI)
	str += fmt.Sprintf("Signature Algorithms: %#v\n", ch.SignatureAlgs)
	str += fmt.Sprintf("Groups: %#v\n", ch.SupportedGroups)
	str += fmt.Sprintf("Points: %#v\n", ch.SupportedPoints)
	str += fmt.Sprintf("OSCP: %v\n", ch.OSCP)
	str += fmt.Sprintf("ALPNs: %v \n", ch.ALPNs)
	str += fmt.Sprintf("Handshake Support Versions: %v \n", ch.SupportVersion)
	return str
}

func (ch *ClientHello) decodeFromBytes(payload []byte, df gopacket.DecodeFeedback) error {
	hs := payload[:]

	if len(hs) < 6 {
		return ErrHandshakeBadLength
	}

	ch.HandshakeType = uint8(hs[0])

	if ch.HandshakeType != 1 {
		return ErrHandshakeWrongType
	}
	ch.HandshakeLen = uint32(hs[1])<<16 | uint32(hs[2])<<8 | uint32(hs[3])
	ch.HandshakeVersion = TLSVersion(hs[4])<<8 | TLSVersion(hs[5])

	hs = hs[6:]

	if len(hs) < ClientHelloRandomLen {
		return ErrHandshakeBadLength
	}

	// Get random data
	ch.Random = hs[:ClientHelloRandomLen]

	hs = hs[ClientHelloRandomLen:]

	if len(hs) < 1 {
		return ErrHandshakeBadLength
	}

	// Get SessionID
	ch.SessionIDLen = uint32(hs[0])
	hs = hs[1:]

	if len(hs) < int(ch.SessionIDLen) {
		return ErrHandshakeBadLength
	}

	if ch.SessionIDLen != 0 {
		ch.SessionID = hs[:ch.SessionIDLen]
	}

	hs = hs[ch.SessionIDLen:]

	if len(hs) < 2 {
		return ErrHandshakeBadLength
	}

	// Cipher Suite
	ch.CipherSuiteLen = uint16(hs[0])<<8 | uint16(hs[1])

	numCiphers := ch.CipherSuiteLen / 2

	if len(hs) < int(ch.CipherSuiteLen) {
		return ErrHandshakeBadLength
	}

	ch.CipherSuites = make([]CipherSuite, numCiphers)
	for i := 0; i < int(numCiphers); i++ {
		ch.CipherSuites[i] = CipherSuite(hs[2+2*i])<<8 | CipherSuite(hs[3+2*i])
	}

	hs = hs[2+ch.CipherSuiteLen:]

	if len(hs) < 1 {
		return ErrHandshakeBadLength
	}

	// Compression Methods
	numCompressMethods := int(hs[0])

	if len(hs) < 1+numCompressMethods {
		return ErrHandshakeBadLength
	}

	ch.CompressMethods = make([]uint8, numCompressMethods)
	for i := 0; i < int(numCompressMethods); i++ {
		ch.CompressMethods[i] = uint8(hs[1+1*i])
	}

	hs = hs[1+numCompressMethods:]

	if len(hs) < 2 {
		// No extensions or malformed length
		return ErrHandshakeBadLength
	}

	// Extensions
	ch.ExtensionLen = uint16(hs[0])<<8 | uint16(hs[1])

	if len(hs) < int(ch.ExtensionLen) {
		return ErrHandshakeExtBadLength
	}

	hs = hs[2:]
	ch.Extensions = make(map[Extension]uint16)

	for len(hs) > 0 {
		if len(hs) < 4 {
			return ErrHandshakeExtBadLength
		}

		extType := Extension(hs[0])<<8 | Extension(hs[1])
		length := uint16(hs[2])<<8 | uint16(hs[3])

		if len(hs) < 4+int(length) {
			return ErrHandshakeExtBadLength
		}

		data := hs[4 : 4+length]
		hs = hs[4+length:]

		switch extType {
		case ExtServerName:
			if len(data) < 2 {
				return ErrHandshakeExtBadLength
			}
			sniLen := int(data[0])<<8 | int(data[0])

			data = data[2:]

			if len(data) < sniLen {
				// Malformed SNI data
				return ErrHandshakeExtBadLength
			}

			for len(data) > 0 {
				nameType := data[0]

				if len(data) < 3 {
					// Malformed ServerName
					return ErrHandshakeExtBadLength
				}

				nameLen := int(data[1])<<8 | int(data[2])

				data = data[3:]

				switch nameType {
				case SNINameTypeDNS:
					ch.SNI = string(data)
				default:
					// Unknown Name Type
				}
				data = data[nameLen:]
			}
		case ExtSignatureAlgs:
			if len(data) < 2 {
				return ErrHandshakeExtBadLength
			}
			sigLen := int(data[0])<<8 | int(data[1])

			data = data[2:]

			if len(data) < sigLen {
				return ErrHandshakeExtBadLength
			}

			ch.SignatureAlgs = make([]uint16, sigLen/2)

			for i := 0; i < sigLen/2; i++ {
				ch.SignatureAlgs[i] = uint16(data[i*2])<<8 | uint16(data[i*2+1])
			}
		case ExtSupportedGroups:
			if len(data) < 2 {
				return ErrHandshakeExtBadLength
			}
			groupLen := int(data[0])<<8 | int(data[1])

			data = data[2:]

			if len(data) < groupLen {
				// Malformed length
				return ErrHandshakeExtBadLength
			}

			ch.SupportedGroups = make([]uint16, groupLen/2)
			for i := 0; i < groupLen/2; i++ {
				ch.SupportedGroups[i] = uint16(data[i*2])<<8 | uint16(data[i*2+1])
			}
		case ExtECPointFormats:
			if len(data) < 1 {
				return ErrHandshakeExtBadLength
			}
			pointLen := int(data[0])

			data = data[1:]

			if len(data) < pointLen {
				return ErrHandshakeExtBadLength
			}

			ch.SupportedPoints = make([]uint8, pointLen)
			for i := 0; i < pointLen; i++ {
				ch.SupportedPoints[i] = uint8(data[i])
			}

		case ExtStatusRequest:
			if len(data) < 1 {
				return ErrHandshakeExtBadLength
			}

			switch data[0] {
			case OCSPStatusRequest:
				ch.OSCP = true
			}
		case ExtALPN:
			if len(data) < 2 {
				return ErrHandshakeExtBadLength
			}

			alpnLen := int(data[0])<<8 | int(data[1])
			data = data[2:]

			if len(data) != alpnLen {
				return ErrHandshakeExtBadLength
			}

			for len(data) > 0 {
				stringLen := int(data[0])
				data = data[1:]
				ch.ALPNs = append(ch.ALPNs, string(data[:stringLen]))
				data = data[stringLen:]
			}
		case ExtSupportVersions:
			if len(data) < 1 {
				return ErrHandshakeExtBadLength
			}
			sptVerLen := int(data[0])
			data = data[1:]

			for i := 0; i < sptVerLen/2; i++ {
				ch.SupportVersion = append(ch.SupportVersion, TLSVersion(uint16(data[1])|uint16(data[0])<<8))
				data = data[2:]
			}

		default:
			// Other extension where we only care about presence, or presence
			// and length or unknown extension
			ch.Extensions[extType] = length
		}

	}
	return nil
}

type ServerHello struct {
	HandshakeType    uint8
	HandshakeLen     uint32
	HandshakeVersion TLSVersion
	SupportVersion   []TLSVersion
	Random           []byte
	SessionIDLen     uint32
	SessionID        []byte
	CipherSuites     CipherSuite
	CompressMethods  uint8
	ExtensionLen     uint16
	ALPN             string
	Extensions       map[Extension]uint16 // [Type]Length
}

func (sh ServerHello) String() string {
	str := fmt.Sprintln("Handshake Type:", sh.HandshakeType)
	str += fmt.Sprintln("Handshake Version:", sh.GetTLSVersion())
	str += fmt.Sprintf("Cipher Suites %v\n", sh.CipherSuites)
	str += fmt.Sprintf("SessionID: %#v\n", sh.SessionID)
	str += fmt.Sprintln("Random: ", hex.EncodeToString(sh.Random))
	str += fmt.Sprintf("Support TLS Verion:%v \n", sh.SupportVersion)
	return str
}

func (sh ServerHello) GetTLSCipherSuite() uint16 {
	return uint16(sh.CipherSuites)
}

func (sh ServerHello) GetTLSVersion() TLSVersion {
	var mxv = sh.HandshakeVersion
	for _, v := range sh.SupportVersion {
		if v >= mxv {
			mxv = v
		}
	}
	return mxv
}

func (sh *ServerHello) decodeFromBytes(payload []byte, df gopacket.DecodeFeedback) error {
	hs := payload[:]

	if len(hs) < 6 {
		return ErrHandshakeBadLength
	}

	sh.HandshakeType = uint8(hs[0])

	if sh.HandshakeType != 2 {
		return ErrHandshakeWrongType
	}
	sh.HandshakeLen = uint32(hs[1])<<16 | uint32(hs[2])<<8 | uint32(hs[3])
	sh.HandshakeVersion = TLSVersion(hs[4])<<8 | TLSVersion(hs[5])

	hs = hs[6:]

	if len(hs) < ClientHelloRandomLen {
		return ErrHandshakeBadLength
	}

	// Get random data
	sh.Random = hs[:ClientHelloRandomLen]

	hs = hs[ClientHelloRandomLen:]

	if len(hs) < 1 {
		return ErrHandshakeBadLength
	}

	// Get SessionID
	sh.SessionIDLen = uint32(hs[0])
	hs = hs[1:]

	if len(hs) < int(sh.SessionIDLen) {
		return ErrHandshakeBadLength
	}

	if sh.SessionIDLen != 0 {
		sh.SessionID = hs[:sh.SessionIDLen]
	}

	hs = hs[sh.SessionIDLen:]

	if len(hs) < 2 {
		return ErrHandshakeBadLength
	}

	// Cipher Suite

	//cipherSuite,_ := strconv.ParseUint(hex.EncodeToString(hs[:2]),16,32)
	sh.CipherSuites = CipherSuite(hs[0])<<8 | CipherSuite(hs[1])
	hs = hs[2:]

	if len(hs) < 2 {
		return ErrHandshakeBadLength
	}

	// CompressMethods
	sh.CompressMethods = uint8(hs[0])

	hs = hs[1:]

	if len(hs) < 2 {
		return ErrHandshakeBadLength
	}

	// Extension
	sh.ExtensionLen = uint16(hs[0])<<8 | uint16(hs[1])

	if len(hs) < int(sh.ExtensionLen) {
		return ErrHandshakeExtBadLength
	}

	hs = hs[2:]
	sh.Extensions = make(map[Extension]uint16)

	for len(hs) > 0 {
		if len(hs) < 4 {
			return ErrHandshakeExtBadLength
		}

		extType := Extension(hs[0])<<8 | Extension(hs[1])
		length := uint16(hs[2])<<8 | uint16(hs[3])

		if len(hs) < 4+int(length) {
			return ErrHandshakeExtBadLength
		}

		data := hs[4 : 4+length]
		hs = hs[4+length:]

		switch extType {
		case ExtSupportVersions:
			if len(data) < 1 {
				return ErrHandshakeExtBadLength
			}

			sh.SupportVersion = append(sh.SupportVersion, TLSVersion(uint16(data[1])|uint16(data[0])<<8))
		case ExtALPN:
			if len(data) < 2 {
				return ErrHandshakeExtBadLength
			}

			alpnLen := int(data[0])<<8 | int(data[1])
			data = data[2:]

			if len(data) != alpnLen {
				return ErrHandshakeExtBadLength
			}

			for len(data) > 0 {
				stringLen := int(data[0])
				data = data[1:]
				sh.ALPN = string(data[:stringLen])
				data = data[stringLen:]
			}

		default:
			// Other extension where we only care about presence, or presence
			// and length or unknown extension
			sh.Extensions[extType] = length
		}
	}

	return nil
}

type EncryptedExtension struct {
	HandshakeType uint8
	HandshakeLen  uint32
	ALPN          string
	ExtensionLen  uint16
	Extensions    map[Extension]uint16 // [Type]Length
}

func (ee *EncryptedExtension) decodeFromBytes(payload []byte, df gopacket.DecodeFeedback) error {
	hs := payload[:]

	if len(hs) < 6 {
		return ErrHandshakeBadLength
	}

	ee.HandshakeType = uint8(hs[0])
	if ee.HandshakeType != 8 {
		return ErrHandshakeWrongType
	}
	ee.HandshakeLen = uint32(hs[1])<<16 | uint32(hs[2])<<8 | uint32(hs[3])
	hs = hs[4:]

	// Extensions
	ee.ExtensionLen = uint16(hs[0])<<8 | uint16(hs[1])

	if len(hs) < int(ee.ExtensionLen) {
		return ErrHandshakeExtBadLength
	}

	hs = hs[2:]
	ee.Extensions = make(map[Extension]uint16)

	for len(hs) > 0 {
		if len(hs) < 4 {
			return ErrHandshakeExtBadLength
		}

		extType := Extension(hs[0])<<8 | Extension(hs[1])
		length := uint16(hs[2])<<8 | uint16(hs[3])

		if len(hs) < 4+int(length) {
			return ErrHandshakeExtBadLength
		}

		data := hs[4 : 4+length]
		hs = hs[4+length:]

		switch extType {
		case ExtSupportVersions:
			if len(data) < 1 {
				return ErrHandshakeExtBadLength
			}
		case ExtALPN:
			if len(data) < 2 {
				return ErrHandshakeExtBadLength
			}

			alpnLen := int(data[0])<<8 | int(data[1])
			data = data[2:]

			if len(data) != alpnLen {
				return ErrHandshakeExtBadLength
			}

			for len(data) > 0 {
				stringLen := int(data[0])
				data = data[1:]
				ee.ALPN = string(data[:stringLen])
				data = data[stringLen:]
			}

		default:
			// Other extension where we only care about presence, or presence
			// and length or unknown extension
			ee.Extensions[extType] = length
		}
	}
	return nil
}

type Finished struct {
	HandshakeType uint8
	HandshakeLen  uint32
}
