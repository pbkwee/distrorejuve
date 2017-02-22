# a script to test processing/handling of various repository lines we are expected to see
# to test
# bash repolines.sh  | grep -v '==='>b ; diff expectedreposlines.txt b; rm -f b

declare -a REPOSLINES=(" deb file:///usr/local/packages/ stable main" \
" deb file:/var/cache/apt-build/repository apt-build main" \
" deb ftp://mirrors.usc.edu/pub/linux/distributions/debian/ lenny main contrib non-free" \
" deb http://archive.debian.org/debian-archive/debian-security/ lenny/updates main contrib non-free" \
" deb http://archive.debian.org/debian-backports lenny-backports main" \
" deb http://archive.debian.org/debian etch main" \
" deb http://archive.debian.org/debian etch main contrib" \
" deb http://archive.debian.org/debian lenny main" \
" deb http://archive.debian.org/debian/ lenny main contrib non-free" \
" deb http://archive.debian.org/debian lenny non-free" \
" deb http://archive.debian.org/debian-security etch/updates main contrib non-free" \
" deb http://archive.debian.org/debian-security lenny/updates main contrib non-free" \
" deb http://archive.debian.org/debian-security sarge/updates main contrib non-free" \
" deb http://archive.debian.org/debian-volatile lenny/volatile main contrib non-free" \
" deb http://archive.debian.org/debian woody contrib main non-free" \
" deb http://archive.debian.org/debian woody main contrib non-free" \
" deb http://archive.ubuntu.com/ubuntu trusty main restricted" \
" deb http://archive.ubuntu.com/ubuntu trusty multiverse" \
" deb http://archive.ubuntu.com/ubuntu trusty universe" \
" deb http://archive.ubuntu.com/ubuntu trusty-updates main restricted" \
" deb http://archive.ubuntu.com/ubuntu trusty-updates multiverse" \
" deb http://archive.ubuntu.com/ubuntu trusty-updates universe" \
" deb http://autoinstall.plesk.com/debian/BILLING_11.5.30 all all" \
" deb http://autoinstall.plesk.com/debian/PSA_11.5.30 squeeze all" \
" deb http://autoinstall.plesk.com/debian/SITEBUILDER_11.5.10 all all" \
" deb http://debian.example.net.nz/debian lenny awm" \
" deb http://downloads-distro.mongodb.org/repo/debian-sysvinit dist 10gen" \
" deb http://downloads.mongodb.org/distros/debian 5.0 10gen" \
" deb http://downloads.mongodb.org/distros/ubuntu 9.10 10gen" \
" deb http://download.webmin.com/download/repository sarge contrib # disabled on upgrade to raring" \
" deb http://ftp.au.debian.org/debian lenny main contrib" \
" deb http://ftp.debian.org/debian/ etch main non-free" \
" deb http://ftp.debian.org/debian/ lenny main contrib non-free" \
" deb http://ftp.debian.org/debian/ unstable main non-free" \
" deb http://ftp.es.debian.org/debian/ squeeze main contrib non-free" \
" deb http://ftp.nz.debian.org/debian/ lenny main" \
" deb http://ftp.nz.debian.org/debian stable main contrib non-free" \
" deb http://ftp.example.jp/Linux/debian/debian-archive/debian etch main contrib non-free" \
" deb http://ftp.uk.debian.org/debian lenny main contrib non-free" \
" deb http://ftp.us.debian.org/debian sarge main contrib" \
" deb http://ftp.us.debian.org/debian squeeze main contrib" \
" deb http://ftp.us.debian.org/debian squeeze main contrib non-free" \
" deb http://ftp.us.debian.org/debian/ stable main" \
" deb http://ftp.us.debian.org/debian/ stable main contrib non-free" \
" deb http://ftp.us.debian.org/debian stretch main contrib non-free" \
" deb http://http.debian.net/debian squeeze-lts main contrib non-free" \
" deb http://http.us.debian.org/debian lenny main" \
" deb http://http.us.debian.org/debian lenny main contrib non-free" \
" deb http://http.us.debian.org/debian/ stable main contrib non-free" \
" deb http://example.sourceforge.net/debian ./" \
" deb http://non-us.debian.org/debian-non-US sarge/non-US main contrib non-free" \
" deb http://old-releases.ubuntu.com/ubuntu/ hardy main restricted universe multiverse" \
" deb http://old-releases.ubuntu.com/ubuntu/ hardy-security main restricted universe multiverse" \
" deb http://old-releases.ubuntu.com/ubuntu/ hardy-updates main restricted universe multiverse" \
" deb http://opensource.example.net/debian/php5-eaccelerator ./" \
" deb http://packages.dotdeb.org oldstable all" \
" deb http://packages.dotdeb.org sarge all" \
" deb http://php53.dotdeb.org lenny all" \
" deb http://php53.dotdeb.org oldstable all" \
" deb http://ppa.launchpad.net/damokles/ubuntu hardy main" \
" deb http://security.debian.org lenny/updates main contrib non-free" \
" deb http://security.debian.org/ sarge/updates main" \
" deb http://security.debian.org sarge/updates main contrib non-free" \
" deb http://security.debian.org/ squeeze/updates main" \
" deb http://security.debian.org squeeze/updates main contrib non-free" \
" deb http://security.debian.org/ stable/updates main contrib non-free" \
" deb http://security.debian.org stretch/updates main contrib non-free" \
" deb http://security.debian.org testing/updates main contrib non-free" \
" deb http://security.ubuntu.com/ubuntu trusty-security main restricted" \
" deb http://security.ubuntu.com/ubuntu trusty-security multiverse" \
" deb http://security.ubuntu.com/ubuntu trusty-security universe" \
" deb https://sdkrepo.example.com/debian/ stable contrib" \
" deb http://volatile.debian.net/debian-volatile etch/volatile main contrib non-free" \
" deb http://volatile.debian.org/debian-volatile lenny/volatile main" \
" deb http://webmin.mirror.example.co.uk/repository sarge contrib" \
" deb http://www.backports.org/backports.org/ lenny-backports main contrib non-free" \
" deb http://www.backports.org/backports.org/ sarge-backports main contrib non-free" \
" deb http://www.backports.org/debian lenny-backports main contrib non-free" \
" deb http://www.debian-multimedia.org etch main" \
" deb http://www.debian-multimedia.org lenny main" \
" deb http://www.example.com/debian etch main" \
" deb http://www.example.jp/~example/apt/etch/ ./" \
" deb http://www.rabbitmq.com/debian/ testing main" \
" deb http://www.example.com/downloads/linux/debian lenny main" \
" deb http://archive.debian.org/debian sarge main contrib non-free" \
" deb http://archive.debian.org/debian-security/ lenny/updates main contrib non-free" \
" deb http://archive.debian.org/debian/ woody main non-free contrib" \
" deb http://download.webmin.com/download/repository sarge contrib" \
" deb http://ftp.us.debian.org/debian/ lenny main contrib non-free" \
" deb http://ftp.us.debian.org/debian sid main contrib non-free" \
" deb http://ftp.us.debian.org/debian squeeze-lts main non-free contrib" \
" deb http://http.us.debian.org/debian testing main contrib non-free" \
" deb http://packages.dotdeb.org lenny all" \
" deb http://packages.dotdeb.org stable all" \
" deb http://security.debian.org stable/updates main contrib non-free" \
" deb http://archive.debian.org/debian-archive/debian/ lenny main contrib non-free" \
" deb http://archive.debian.org/debian etch main contrib non-free" \
" deb http://ftp.nz.debian.org/debian lenny main contrib" \
" deb http://archive.debian.org/debian-archive/debian lenny main contrib non-free" \
" deb http://archive.debian.org/ lenny/updates main" \
" deb http://ftp.us.debian.org/debian/ squeeze main non-free contrib" \
" deb http://http.us.debian.org/debian sarge main contrib non-free" \
" deb http://security.debian.org/ squeeze/updates main non-free contrib" \
" deb http://software.virtualmin.com/gpl/debian/ virtualmin-lenny main" \
" deb http://software.virtualmin.com/gpl/debian/ virtualmin-universal main" \
" deb http://www.backports.org/debian etch-backports main contrib non-free" \
" deb http://archive.debian.org/debian/ sarge main non-free contrib" \
" deb http://archive.debian.org/debian-security lenny/updates main" \
" deb http://autoinstall.plesk.com/debian/BILLING_10.4.4 all all" \
" deb http://autoinstall.plesk.com/debian/PSA_10.4.4 lenny all" \
" deb http://autoinstall.plesk.com/debian/SITEBUILDER_10.4.4 all all" \
" deb http://archive.debian.org/debian lenny main contrib non-free" \
" deb http://archive.debian.org/debian lenny main contrib" \
" deb http://archive.debian.org/debian/ etch main non-free contrib" \
" deb http://apt.postgresql.org/pub/repos/apt/ squeeze-pgdg main 9.2" \
" deb http://backports.debian.org/debian-backports/ squeeze-backports main contrib non-free" \
" deb http://ftp.us.debian.org/debian/ squeeze main contrib non-free" \
" deb http://packages.example.com/example/ lenny/" \
" deb http://security.debian.org/ squeeze/updates main contrib non-free" \
" deb http://http.debian.net/debian/ squeeze-lts main contrib non-free" \
" deb http://archive.debian.org/debian/ lenny main non-free contrib")

name=squeeze
for ((i=0;i<${#REPOSLINES[@]};i++)); do
line="${REPOSLINES[$i]]}"
for distro in lenny woody trusty etch sarge; do
 line=$(echo $line | sed "s/$distro/$name/g")
done
name2=foobar
echo $line===
echo $line | egrep -qai "^ *deb ([a-zA-Z]+)://([-~a-zA-Z0-9./]*) +$name[ /]" && echo $line | sed "s@^ *deb \([a-zA-Z]*\)://\([-~a-zA-Z0-9./]*\) *$name\([ /]\)@deb \1://\2 $name2\3@"
done

