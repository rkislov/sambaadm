import socket
import dns.message,dns.rrset,dns.rdatatype,dns.flags
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',53))
while True:
 raw,addr=s.recvfrom(65535);q=dns.message.from_wire(raw);r=dns.message.make_response(q);r.flags|=dns.flags.AA
 if q.question and q.question[0].rdtype==dns.rdatatype.A:r.answer.append(dns.rrset.from_text(q.question[0].name,30,'IN','A','198.51.100.24'))
 s.sendto(r.to_wire(),addr)
