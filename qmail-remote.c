#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <idn2.h>
#include "sig.h"
#include "stralloc.h"
#include "substdio.h"
#include "subfd.h"
#include "scan.h"
#include "case.h"
#include "error.h"
#include "auto_qmail.h"
#include "control.h"
#include "dns.h"
#include "alloc.h"
#include "quote.h"
#include "ip.h"
#include "ipalloc.h"
#include "ipme.h"
#include "gen_alloc.h"
#include "gen_allocdefs.h"
#include "str.h"
#include "now.h"
#include "exit.h"
#include "constmap.h"
#include "tcpto.h"
#include "readwrite.h"
#include "timeoutconn.h"
#include "timeoutread.h"
#include "timeoutwrite.h"

#define HUGESMTPTEXT 5000

#define PORT_SMTP 25 /* silly rabbit, /etc/services is for users */
unsigned long port = PORT_SMTP;

GEN_ALLOC_typedef(saa,stralloc,sa,len,a)
GEN_ALLOC_readyplus(saa,stralloc,sa,len,a,i,n,x,10,saa_readyplus)
static stralloc sauninit = {0};

stralloc helohost = {0};
stralloc routes = {0};
struct constmap maproutes;
stralloc host = {0};
stralloc asciihost = {0};
stralloc sender = {0};

saa reciplist = {0};

struct ip_address partner;

void out(s) char *s; { if (substdio_puts(subfdoutsmall,s) == -1) _exit(0); }
void zero() { if (substdio_put(subfdoutsmall,"\0",1) == -1) _exit(0); }
void zerodie() { zero(); substdio_flush(subfdoutsmall); _exit(0); }
void outsafe(sa) stralloc *sa; { int i; char ch;
for (i = 0;i < sa->len;++i) {
ch = sa->s[i]; if (ch < 33) ch = '?'; if (ch > 126) ch = '?';
if (substdio_put(subfdoutsmall,&ch,1) == -1) _exit(0); } }

void temp_nomem() { out("ZOut of memory. (#4.3.0)\n"); zerodie(); }
void temp_oserr() { out("Z\
System resources temporarily unavailable. (#4.3.0)\n"); zerodie(); }
void temp_noconn() { out("Z\
Sorry, I wasn't able to establish an SMTP connection. (#4.4.1)\n"); zerodie(); }
void temp_read() { out("ZUnable to read message. (#4.3.0)\n"); zerodie(); }
void temp_dnscanon() { out("Z\
CNAME lookup failed temporarily. (#4.4.3)\n"); zerodie(); }
void temp_dns() { out("Z\
Sorry, I couldn't find any host by that name. (#4.1.2)\n"); zerodie(); }
void temp_chdir() { out("Z\
Unable to switch to home directory. (#4.3.0)\n"); zerodie(); }
void temp_control() { out("Z\
Unable to read control files. (#4.3.0)\n"); zerodie(); }
void perm_partialline() { out("D\
SMTP cannot transfer messages with partial final lines. (#5.6.2)\n"); zerodie(); }
void perm_usage() { out("D\
I (qmail-remote) was invoked improperly. (#5.3.5)\n"); zerodie(); }
void perm_dns() { out("D\
Sorry, I couldn't find any host named ");
outsafe(&host);
out(". (#5.1.2)\n"); zerodie(); }
void perm_nomx() { out("D\
Sorry, I couldn't find a mail exchanger or IP address. (#5.4.4)\n");
zerodie(); }
void perm_ambigmx() { out("D\
Sorry. Although I'm listed as a best-preference MX or A for that host,\n\
it isn't in my control/locals file, so I don't treat it as local. (#5.4.6)\n");
zerodie(); }

void outhost()
{
  char x[IPFMT];
  if (substdio_put(subfdoutsmall,x,ip_fmt(x,&partner)) == -1) _exit(0);
}

int flagcritical = 0;

void dropped() {
  out("ZConnected to ");
  outhost();
  out(" but connection died. ");
  if (flagcritical) out("Possible duplicate! ");
  out("(#4.4.2)\n");
  zerodie();
}

int timeoutconnect = 60;
int smtpfd;
int timeout = 1200;

int saferead(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  r = timeoutread(timeout,smtpfd,buf,len);
  if (r <= 0) dropped();
  return r;
}
int safewrite(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  r = timeoutwrite(timeout,smtpfd,buf,len);
  if (r <= 0) dropped();
  return r;
}

char inbuf[1024];
substdio ssin = SUBSTDIO_FDBUF(read,0,inbuf,sizeof inbuf);
char smtptobuf[1024];
substdio smtpto = SUBSTDIO_FDBUF(safewrite,-1,smtptobuf,sizeof smtptobuf);
char smtpfrombuf[128];
substdio smtpfrom = SUBSTDIO_FDBUF(saferead,-1,smtpfrombuf,sizeof smtpfrombuf);

stralloc smtptext = {0};
stralloc firstpart = {0};

void get(ch)
char *ch;
{
  substdio_get(&smtpfrom,ch,1);
  if (*ch != '\r')
    if (smtptext.len < HUGESMTPTEXT)
     if (!stralloc_append(&smtptext,ch)) temp_nomem();
}


struct keywords {
  char *text;
  int *seen;
} ;

int esmtp = 0;

struct keywords bannerkeywords[] = {
  { "esmtp", &esmtp }
, { 0, 0 }
} ;

int smtputf8 = 0;


struct keywords ehlokeywords[] = {
  { "smtputf8", &smtputf8 }
, { 0, 0 }
} ;


void smtpline(kw, ch)
struct keywords * kw;
unsigned char ch;
{
  unsigned char lineprefix[1024];
  unsigned char pos = 0;
  int k;

  while (ch != '\n') {
    if (kw) if (pos < 1023) lineprefix[pos++] = ch;
    get(&ch);
  }
  if (!kw) return;
  lineprefix[pos++] = '\0';
  for (k = 0;kw[k].text;++k) {
    int p = 0;
    while (p < pos && !*(kw[k].seen)) {
      if ((p == 0 || lineprefix[p-1] == ' ' || lineprefix[p-1] == '-') &&
          case_starts(lineprefix + p, kw[k].text))
        *(kw[k].seen) = 1;
      p++;
    }
  }
}


unsigned long smtpcode(kw)
struct keywords * kw;
{
  unsigned char ch;
  unsigned long code;

  if (!stralloc_copys(&smtptext,"")) temp_nomem();

  get(&ch); code = ch - '0';
  get(&ch); code = code * 10 + (ch - '0');
  get(&ch); code = code * 10 + (ch - '0');
  for (;;) {
    get(&ch);
    if (ch != '-') break;
    smtpline(kw, ch);
    get(&ch);
    get(&ch);
    get(&ch);
  }
  smtpline(kw, ch);

  return code;
}

void outsmtptext()
{
  int i;
  if (smtptext.s) if (smtptext.len) {
    out("Remote host said: ");
    for (i = 0;i < smtptext.len;++i)
      if (!smtptext.s[i]) smtptext.s[i] = '?';
    if (substdio_put(subfdoutsmall,smtptext.s,smtptext.len) == -1) _exit(0);
    smtptext.len = 0;
  }
}

void quit(prepend,append)
char *prepend;
char *append;
{
  substdio_putsflush(&smtpto,"QUIT\r\n");
  /* waiting for remote side is just too ridiculous */
  out(prepend);
  outhost();
  out(append);
  out(".\n");
  outsmtptext();
  zerodie();
}

void blast()
{
  int r;
  char ch;

  substdio_put(&smtpto,firstpart.s,firstpart.len);

  for (;;) {
    r = substdio_get(&ssin,&ch,1);
    if (r == 0) break;
    if (r == -1) temp_read();
    if (ch == '.')
      substdio_put(&smtpto,".",1);
    while (ch != '\n') {
      substdio_put(&smtpto,&ch,1);
      r = substdio_get(&ssin,&ch,1);
      if (r == 0) perm_partialline();
      if (r == -1) temp_read();
    }
    substdio_put(&smtpto,"\r\n",2);
  }

  flagcritical = 1;
  substdio_put(&smtpto,".\r\n",3);
  substdio_flush(&smtpto);
}

stralloc recip = {0};


int containsutf8(p, l) unsigned char * p; int l;
{
  int i = 0;
  while (i<l)
    if(p[i++] > 127) return 1;
  return 0;
}


int utf8message;

void checkutf8message()
{
  int pos;
  int i;
  int r;
  char ch;
  int state;

  if (containsutf8(sender.s, sender.len)) { utf8message = 1; return; }
  for (i = 0;i < reciplist.len;++i)
    if (containsutf8(reciplist.sa[i].s, reciplist.sa[i].len)) {
      utf8message = 1;
      return;
    }

  state = 0;
  pos = 0;
  for (;;) {
    r = substdio_get(&ssin,&ch,1);
    if (r == 0) break;
    if (r == -1) temp_read();

    if (ch == '\n' && !stralloc_cats(&firstpart,"\r")) temp_nomem();
    if (!stralloc_append(&firstpart,&ch)) temp_nomem();

    if (ch == '\r')
      continue;
    if (ch == '\t')
      ch = ' ';

    switch (state) {
    case 6: /* in Received, at LF but before WITH clause */
      if (ch == ' ') { state = 3; pos = 1; continue; }
      state = 0;
      /* FALL THROUGH */

    case 0: /* start of header field */
      if (ch == '\n') return;
      state = 1;
      pos = 0;
      /* FALL THROUGH */

    case 1: /* partway through "Received:" */
      if (ch != "RECEIVED:"[pos] && ch != "received:"[pos]) { state = 2; continue; }
      if (++pos == 9) { state = 3; pos = 0; }
      continue;

    case 2: /* other header field */
      if (ch == '\n') state = 0;
      continue;

    case 3: /* in Received, before WITH clause or partway though " with " */
      if (ch == '\n') { state = 6; continue; }
      if (ch != " WITH "[pos] && ch != " with "[pos]) { pos = 0; continue; }
      if (++pos == 6) { state = 4; pos = 0; }
      continue;

    case 4: /* in Received, having seen with, before the argument */
      if (pos == 0 && ch == ' ') continue;
      if (ch != "UTF8"[pos] && ch != "utf8"[pos]) { state = 5; continue; }
      if(++pos == 4) { utf8message = 1; state = 5; continue; }
      continue;

    case 5: /* after the RECEIVED WITH argument */
      /* blast() assumes that it copies whole lines */
      if (ch == '\n') return;
      state = 1;
      pos = 0;
      continue;
    }
  }
}

void smtp()
{
  unsigned long code;
  int flagbother;
  int i;

  if (smtpcode(&bannerkeywords) != 220)
    quit("ZConnected to "," but greeting failed");


  substdio_puts(&smtpto,(esmtp ? "EHLO " : "HELO "));
  substdio_put(&smtpto,helohost.s,helohost.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  if (smtpcode(esmtp ? ehlokeywords : 0) != 250)
    quit("ZConnected to "," but my name was rejected");

  checkutf8message();
  if (utf8message && !smtputf8) quit("DConnected to "," but server does not support unicode in email addresses");

  substdio_puts(&smtpto,"MAIL FROM:<");
  substdio_put(&smtpto,sender.s,sender.len);
  substdio_puts(&smtpto,">");
  if (utf8message) substdio_puts(&smtpto," smtputf8");
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  code = smtpcode(0);
  if (code >= 500) quit("DConnected to "," but sender was rejected");
  if (code >= 400) quit("ZConnected to "," but sender was rejected");

  flagbother = 0;
  for (i = 0;i < reciplist.len;++i) {
    substdio_puts(&smtpto,"RCPT TO:<");
    substdio_put(&smtpto,reciplist.sa[i].s,reciplist.sa[i].len);
    substdio_puts(&smtpto,">\r\n");
    substdio_flush(&smtpto);
    code = smtpcode(0);
    if (code >= 500) {
      out("h"); outhost(); out(" does not like recipient.\n");
      outsmtptext(); zero();
    }
    else if (code >= 400) {
      out("s"); outhost(); out(" does not like recipient.\n");
      outsmtptext(); zero();
    }
    else {
      out("r"); zero();
      flagbother = 1;
    }
  }
  if (!flagbother) quit("DGiving up on ","");

  substdio_putsflush(&smtpto,"DATA\r\n");
  code = smtpcode(0);
  if (code >= 500) quit("D"," failed on DATA command");
  if (code >= 400) quit("Z"," failed on DATA command");

  blast();
  code = smtpcode(0);
  flagcritical = 0;
  if (code >= 500) quit("D"," failed after I sent the message");
  if (code >= 400) quit("Z"," failed after I sent the message");
  quit("K"," accepted message");
}

stralloc canonhost = {0};
stralloc canonbox = {0};

void addrmangle(saout,s,flagalias,flagcname)
stralloc *saout; /* host has to be canonical, box has to be quoted */
char *s;
int *flagalias;
int flagcname;
{
  int j;

  *flagalias = flagcname;

  j = str_rchr(s,'@');
  if (!s[j]) {
    if (!stralloc_copys(saout,s)) temp_nomem();
    return;
  }
  if (!stralloc_copys(&canonbox,s)) temp_nomem();
  canonbox.len = j;
  if (!quote(saout,&canonbox)) temp_nomem();
  if (!stralloc_cats(saout,"@")) temp_nomem();

  if (!stralloc_copys(&canonhost,s + j + 1)) temp_nomem();
  if (flagcname)
    switch(dns_cname(&canonhost)) {
      case 0: *flagalias = 0; break;
      case DNS_MEM: temp_nomem();
      case DNS_SOFT: temp_dnscanon();
      case DNS_HARD: ; /* alias loop, not our problem */
    }

  if (!stralloc_cat(saout,&canonhost)) temp_nomem();
}

void getcontrols()
{
  if (control_init() == -1) temp_control();
  if (control_readint(&timeout,"control/timeoutremote") == -1) temp_control();
  if (control_readint(&timeoutconnect,"control/timeoutconnect") == -1)
    temp_control();
  if (control_rldef(&helohost,"control/helohost",1,(char *) 0) != 1)
    temp_control();
  switch(control_readfile(&routes,"control/smtproutes",0)) {
    case -1:
      temp_control();
    case 0:
      if (!constmap_init(&maproutes,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&maproutes,routes.s,routes.len,1)) temp_nomem(); break;
  }
}

void main(argc,argv)
int argc;
char **argv;
{
  static ipalloc ip = {0};
  int i;
  unsigned long random;
  char **recips;
  unsigned long prefme;
  int flagallaliases;
  int flagalias;
  char *relayhost;

  sig_pipeignore();
  if (argc < 4) perm_usage();
  if (chdir(auto_qmail) == -1) temp_chdir();
  getcontrols();


  if (!stralloc_copys(&host,argv[1])) temp_nomem();

  relayhost = 0;
  for (i = 0;i <= host.len;++i)
    if ((i == 0) || (i == host.len) || (host.s[i] == '.'))
      if (relayhost = constmap(&maproutes,host.s + i,host.len - i))
        break;
  if (relayhost && !*relayhost) relayhost = 0;

  if (relayhost) {
    i = str_chr(relayhost,':');
    if (relayhost[i]) {
      scan_ulong(relayhost + i + 1,&port);
      relayhost[i] = 0;
    }
    if (!stralloc_copys(&host,relayhost)) temp_nomem();
  } else {
    char * ascii;
    host.s[host.len] = '\0';
    switch (idn2_lookup_u8(host.s, (uint8_t**)&ascii, IDN2_NFC_INPUT)) {
      case IDN2_OK: break;
      case IDN2_MALLOC: temp_nomem();
      default: perm_dns();
    }
    if (!stralloc_copys(&asciihost, ascii)) temp_nomem();
  }


  addrmangle(&sender,argv[2],&flagalias,0);

  if (!saa_readyplus(&reciplist,0)) temp_nomem();
  if (ipme_init() != 1) temp_oserr();

  flagallaliases = 1;
  recips = argv + 3;
  while (*recips) {
    if (!saa_readyplus(&reciplist,1)) temp_nomem();
    reciplist.sa[reciplist.len] = sauninit;
    addrmangle(reciplist.sa + reciplist.len,*recips,&flagalias,!relayhost);
    if (!flagalias) flagallaliases = 0;
    ++reciplist.len;
    ++recips;
  }


  random = now() + (getpid() << 16);
  switch (relayhost ? dns_ip(&ip,&host) : dns_mxip(&ip,&asciihost,random)) {
    case DNS_MEM: temp_nomem();
    case DNS_SOFT: temp_dns();
    case DNS_HARD: perm_dns();
    case 1:
      if (ip.len <= 0) temp_dns();
  }

  if (ip.len <= 0) perm_nomx();

  prefme = 100000;
  for (i = 0;i < ip.len;++i)
    if (ipme_is(&ip.ix[i].ip))
      if (ip.ix[i].pref < prefme)
        prefme = ip.ix[i].pref;

  if (relayhost) prefme = 300000;
  if (flagallaliases) prefme = 500000;

  for (i = 0;i < ip.len;++i)
    if (ip.ix[i].pref < prefme)
      break;

  if (i >= ip.len)
    perm_ambigmx();

  for (i = 0;i < ip.len;++i) if (ip.ix[i].pref < prefme) {
    if (tcpto(&ip.ix[i].ip)) continue;

    smtpfd = socket(AF_INET,SOCK_STREAM,0);
    if (smtpfd == -1) temp_oserr();

    if (timeoutconn(smtpfd,&ip.ix[i].ip,(unsigned int) port,timeoutconnect) == 0) {
      tcpto_err(&ip.ix[i].ip,0);
      partner = ip.ix[i].ip;
      smtp(); /* does not return */
    }
    tcpto_err(&ip.ix[i].ip,errno == error_timeout);
    close(smtpfd);
  }

  temp_noconn();
}
