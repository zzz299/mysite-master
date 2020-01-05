from django.db import models

# Create your models here.
# class TCP(models.Model):
#     sport = models.CharField(max_length=20, default='')
#     dport = models.CharField(max_length=80, default='')
#     seq = models.IntegerField(default=0)
#     ack = models.IntegerField(default=0)
#     dataofs = models.CharField(max_length=20, default='')
#     reversed = models.CharField(max_length=20, default='')
#     flags = models.CharField(max_length=20, default='')
#     window = models.IntegerField(default=0)
#     chksum = models.IntegerField(default=0)
#     urgptr = models.CharField(max_length=20, default='')
#     options = models.CharField(max_length=20, default='')

# def tcp_crt(pcap):
#     tcp = TCP(sport=pcap.sport, dport=pcap.dport, seq=pcap.seq, ack=pcap.ack, dataofs=pcap.datapofs, reversed=pcap.reversed, flags=pcap.flags, window=pcap.window, chksum=pcap.chksum, urgptr=pcap.urgptr, options=pcap.options)
#     tcp.save()
#     return tcp
