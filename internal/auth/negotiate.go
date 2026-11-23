package auth

// HTTP Negotiate adapter. Kerberos ticket verification, replay checks and AP_REP
// encryption use the existing Kerberos libraries; no cryptographic primitive is
// implemented here. The mutual-authentication reply is required by native GSSAPI
// clients and browsers, unlike an empty SPNEGO accept-completed response.
import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
	krbmessages "github.com/oiweiwei/gokrb5.fork/v9/messages"
	krbtypes "github.com/oiweiwei/gokrb5.fork/v9/types"
)

type peerContextKey struct{}

func WithPeerAddress(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, peerContextKey{}, addr)
}
func channelBinding(certDER []byte) []byte {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil
	}
	var digest []byte
	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		sum := sha512.Sum384(certDER)
		digest = sum[:]
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		sum := sha512.Sum512(certDER)
		digest = sum[:]
	default:
		sum := sha256.Sum256(certDER)
		digest = sum[:]
	}
	data := append([]byte("tls-server-end-point:"), digest...)
	bindings := make([]byte, 20)
	binary.LittleEndian.PutUint32(bindings[16:], uint32(len(data)))
	bindings = append(bindings, data...)
	// RFC 4121 requires MD5 of the GSS channel-binding structure, not a signature.
	hash := md5.Sum(bindings)
	return hash[:]
}
func kerberosHTTP(kt *keytab.Keytab, inner http.Handler, certDER []byte) http.Handler {
	binding := channelBinding(certDER)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reject := func() {
			w.Header().Set("WWW-Authenticate", "Negotiate")
			http.Error(w, "Требуется вход с доменным билетом Kerberos", 401)
		}
		header := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(header) != 2 || !strings.EqualFold(header[0], "Negotiate") {
			reject()
			return
		}
		raw, err := base64.StdEncoding.DecodeString(header[1])
		if err != nil {
			reject()
			return
		}
		var negotiation spnego.SPNEGOToken
		mech := raw
		wrapped := false
		if err = negotiation.Unmarshal(raw); err == nil {
			wrapped = true
			if negotiation.Init {
				mech = negotiation.NegTokenInit.MechTokenBytes
			} else if negotiation.Resp {
				mech = negotiation.NegTokenResp.ResponseToken
			} else {
				reject()
				return
			}
		}
		var token spnego.KRB5Token
		if err = token.Unmarshal(mech); err != nil || !token.IsAPReq() || (!token.OID.Equal(gssapi.OIDKRB5.OID()) && !token.OID.Equal(gssapi.OIDMSLegacyKRB5.OID())) {
			reject()
			return
		}
		settings := []func(*service.Settings){service.DecodePAC(false), service.MaxClockSkew(5 * time.Minute)}
		peer := r.RemoteAddr
		if actual, ok := r.Context().Value(peerContextKey{}).(string); ok {
			peer = actual
		}
		if addr, e := types.GetHostAddress(peer); e == nil {
			settings = append(settings, service.ClientAddress(addr))
		}
		ok, creds, err := service.VerifyAPREQ(&token.APReq, service.NewSettings(kt, settings...))
		if err != nil || !ok {
			reject()
			return
		}
		// The encrypted ticket, not an independently supplied authenticator realm,
		// is the authority for the client realm (important for cross-realm tickets).
		if token.APReq.Authenticator.CRealm != token.APReq.Ticket.DecryptedEncPart.CRealm {
			reject()
			return
		}
		checksum := token.APReq.Authenticator.Cksum
		if checksum.CksumType == 32771 {
			if len(checksum.Checksum) < 24 || binary.LittleEndian.Uint32(checksum.Checksum[:4]) != 16 {
				reject()
				return
			}
			supplied := checksum.Checksum[4:20]
			if !bytes.Equal(supplied, make([]byte, 16)) && (len(binding) != 16 || subtle.ConstantTimeCompare(supplied, binding) != 1) {
				reject()
				return
			}
		}
		if !types.IsFlagSet(&token.APReq.APOptions, flags.APOptionMutualRequired) {
			if wrapped {
				response := spnego.SPNEGOToken{Resp: true, NegTokenResp: spnego.NegTokenResp{NegState: asn1.Enumerated(spnego.NegStateAcceptCompleted), SupportedMech: token.OID}}
				data, e := response.Marshal()
				if e != nil {
					reject()
					return
				}
				w.Header().Set("WWW-Authenticate", "Negotiate "+base64.StdEncoding.EncodeToString(data))
			}
			inner.ServeHTTP(w, goidentity.AddToHTTPRequestContext(creds, r))
			return
		}
		sessionKey := token.APReq.Ticket.DecryptedEncPart.Key
		part := krbmessages.NewEncAPRepPart(token.APReq.Authenticator.SeqNumber)
		part.CTime = token.APReq.Authenticator.CTime
		part.Cusec = token.APReq.Authenticator.Cusec
		reply, err := krbmessages.NewAPRep(krbtypes.EncryptionKey{KeyType: sessionKey.KeyType, KeyValue: sessionKey.KeyValue}, part)
		if err != nil {
			reject()
			return
		}
		replyDER, err := reply.Marshal()
		if err != nil {
			reject()
			return
		}
		oidDER, _ := asn1.Marshal(token.OID)
		response := asn1tools.AddASNAppTag(append(append(oidDER, 2, 0), replyDER...), 0)
		if wrapped {
			output := spnego.SPNEGOToken{Resp: true, NegTokenResp: spnego.NegTokenResp{NegState: asn1.Enumerated(spnego.NegStateAcceptCompleted), SupportedMech: token.OID, ResponseToken: response}}
			response, err = output.Marshal()
			if err != nil {
				reject()
				return
			}
		}
		w.Header().Set("WWW-Authenticate", "Negotiate "+base64.StdEncoding.EncodeToString(response))
		inner.ServeHTTP(w, goidentity.AddToHTTPRequestContext(creds, r))
	})
}
