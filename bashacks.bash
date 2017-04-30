#!/usr/bin/env bash

bh_dlsite()
{
	wget -crw $((($RANDOM%10)+1)) \
 --user-agent 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0' \
 "$1"
}

bh_skel_c()
{
	echo -e "#include <stdio.h>\n\nint main(int argc, char *argv[]) {\n\n\n\treturn 0;\n}"
}

bh_isperlm()
{
	[ $# -ne 1 ] && return 1
	perl -M"$1" -e exit &> /dev/null && echo yes ||
	echo no
}

bh_skel_python()
{
	echo -e "#!/usr/bin/env python\n# *-* coding: utf-8 *-*\n\nif __name__ == "__main__":\n\t"
}

bh_asminfo()
{
    [ $# -lt 1 ] && return 1

    local ins=${1,,}

    bh_checkdir

    if test -s $bh_cache/$ins.txt; then
        cat $bh_cache/$ins.txt
	else
        wget -q faydoc.tripod.com/cpu/$ins.htm -O - |
        		 html2text |
        		 sed -n '/^===.*/,$p' |
        		 sed 's/^===.*/'${ins^^}'/' | tr _ ' ' |
        		 tee -a $bh_cache/$ins.txt
     fi

    test -s $bh_cache/$ins.txt || rm -f $bh_cache/$ins.txt

}

bh_intel()
{
	local	GDBINIT="$HOME/.gdbinit"

	if [ "$1" == "on" ]; then
		grep -s 'disassembly-flavor' "$GDBINIT" &> /dev/null || \
		 echo "set disassembly-flavor intel" >> "$GDBINIT"
		alias gdb='gdb -q'
		alias objdump='objdump -M intel-mnemonics'
	elif [ "$1" == "off" ]; then
		sed -i 's/set disassembly-flavor intel//' "$GDBINIT"
		unalias objdump
		unalias gdb
	fi
}

bh_dumpmem()
{
    [ $# -le 1 -o "${EUID}" -ne 0 ] && return 1

    local stack_addr=$(grep -m 1 "$1" /proc/$2/maps |
	            cut -d' ' -f1 | sed 's/^/0x/; s/-/ 0x/')

	test -n "$stack_addr" && \
	        echo "dump memory "$3" $stack_addr" | gdb --pid $2 &> /dev/null
}

alias bh_dumpstack='bh_dumpmem stack'
alias bh_dumpheap='bh_dumpmem heap'

bh_bin2sc()
{
	[ $# -ne 1 ] && return 1
	objdump -D "$1" | perl -ne 's/\b([a-f0-9]{2})\b/print "\\x".$1/ge'
	echo
}

bh_sc2asm()
{
    local mode=32
	local in="$1"

    [ $# -eq 0 ] && return 1

	[ $1 = '-m' ] && mode=$2 in="$3"

	sc=$(echo "$in" | sed 's/\\x/ /g')
	echo "$sc" | udcli -$mode -x -noff -nohex | sed 's/^ //'
}

bh_asmgrep()
{
    [ $# -lt 2 ] && return 1

    objdump -d "$2" | grep --color -C 4 -E "$1"

}

bh_asm2sc()
{
	local obj=$(mktemp)
	local fmt=elf32
	local in="$1"

    [ $#  -eq 0 ] && return 1

    [ $1 = "-f" ] && fmt=$2 in="$3"

	nasm -f $fmt -o $obj $in

	objdump -D $obj | perl -ne's/\b([a-f0-9]{2})\b/print "\\x".$1/ge'
	echo

	rm -f $obj
}

bh_hex2dec()
{
    [ $# -eq 0 ] && return 1

    echo $((0x${1#0x}))
}

bh_dec2hex()
{
    [ $# -eq 0 ] && return 1

    printf "%x\n" "$1"
}

bh_dec2bin()
{
    [ $# -eq 0 ] && return 1
    echo "obase=2;$1" | bc
}

bh_charcalc()
{
    [ $# -ne 3 ] && return 1

    local char
    local chars
    local res
    local i

    case $2 in
        +|-)
            for i in $(echo "$1" | sed 's/./& /g'); do
        		char=$(bh_asc2dec $i)
        		res=$(($char $2 $3))
            		echo -n $(bh_dec2asc $res)
		done
		echo
   		;;
   		'*')
 		    for (( i=0; i<$3; i++ )); do
        	    res="$res$1"
        	done
            echo $res
    	;;
    esac

}

bh_xor()
{
   [ $# -lt 2 ] && return 1

    echo $(($1^$2))
}

bh_pow()
{
    [ $# -lt 2 ] && return 1

    echo $(($1**$2))
}

bh_hexcalc()
{
	test $# -ne 3 && return 1

	echo -n 0x
	bh_dec2hex $((0x${1#0x} $2 0x${3#0x}))
}

bh_shl()
{
    [ $# -lt 2 ] && return 1

    echo $(($1<<$2))
}

bh_bin2dec()
{
    [ $# -eq 0 ] && return 1

    echo $((2#$1))
}

bh_hex2bin()
{
    [ $# -eq 0 ] && return 1

	local bin
	local i

	for i in $*; do
		bin=$(echo "obase=2;ibase=16;$(echo $i | tr a-f A-F)" | bc)
		echo -n "$bin "
    done
	echo
}

bh_shr()
{
    [ $# -lt 2 ] && return 1

    echo $(($1>>$2))
}

bh_md5()
{
    [ $# -eq 0 ] && return 1

	test -e $1 && \
	    md5sum < "$1" | cut -d' ' -f1 \
	       || \
	        echo -n "$1" | md5sum | cut -d' ' -f1
}

bh_rotall()
{
	local i

	test -n "$1" || { bh_rot ; return 1; }

	for i in {1..25}; do
		echo "ROT$i $(bh_rot $i "$1")"
	done
}

alias bh_rot5='bh_rot 5'
alias bh_rot13='bh_rot 13'
alias bh_rot18='bh_rot 18'
alias bh_rot47='bh_rot 47'

bh_rot()
{
    local n

    test $# -eq 2 || return 1

    # n recebe o caractere do alfabeto correspondente
    n=$(echo -e \\x$(bh_dec2hex $(echo -e $((97+$1)))))

    # rot com o tr
    echo $2 | tr a-z $n-za-z | tr A-Z ${n^^}-ZA-Z
}

bh_unmd5()
{
    [ $# -eq 0 ] && return 1

    local sHash="$1"
    local sSite="http://hashtoolkit.com/reverse-hash/?hash=$sHash"

    sA=$(wget -T 30 -q -O - "$sSite" --user-agent="Mozilla/5.0 (Windows NT 6.1; WOW64; rev:28.0) Gecko'20100101 Firefox/28.0" |
        grep -A 1 'res-text' |
        tail -1 |
        sed -e 's/[ ]\+//g ;s/<[^>]*>//g')

    [ ! -z "$sA" ] && [ "$sA" != "$sHash" ] &&
        echo "${sA}"
}

alias bh_unsha512="bh_unmd5"
alias bh_unsha1="bh_unmd5"
alias bh_unsha256="bh_unmd5"
alias bh_unsha356="bh_unmd5"


bh_unbase64()
{
    [ $# -eq 0 ] && return 1
    echo $1 | base64 -d
    echo
}

bh_strxor()
{
    [ $# -lt 2 ] && return 1

    local str
    local xored
    local i

    # $2 is the string and $1 is the xor key
    str=$(bh_str2hex "$2")

    for i in $str; do
       		xored="$xored $(bh_dec2hex $((0x$i^$1)))"
   	done

   	bh_hex2str "$xored"
}

bh_keycheck()
{
	diff <(ssh-keygen -y -f "$1") <(cut -d' ' -f1,2 "$2") >/dev/null && echo \
	'keys match!' || echo 'keys does not match! :('
}

bh_bin2ip()
{
    local sBin="$(echo $1 |
                grep -Ewo '^(([0-1]){8}\.){3}([0-1]){8}$')"

    [ $# -eq 0 -o -z "${sBin}" ] && return 1

	local i
	for i in $(echo "${sBin}" | tr . ' '); do
	    printf "%d." $(bh_bin2dec $i)
    done | sed "s/.$/\\n/"
}

bh_get()
{
	[ "$1" ] || return
	local ua='Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0'
	wget -c --user-agent "$ua" "$1"
}

bh_wscan()
{
    local iFace
    local OUI
    local MAC
    local MACTMP
    local MACPROD
    local PARAM

    [ "$1" == "-i" ] && {
        iFace="$2"
        PARAM="$3"
    } || {
        local iFace="$(iw dev |
        grep 'Interface' |
        cut -d' ' -f2)"
        PARAM="$1"
    }

    [ ${EUID} -ne 0 -o \
        -z "${iFace}" ] && { echo 'root is required' ; return 1; }

    case "$PARAM" in
        -model)
            iw ${iFace} scan -u |
            grep -E '^BSS|Model:' |
            sed -r 's/(\(.*\)|-- associated)//g' |
            tr \\n ' ' |
            sed 's/BSS/\n/g' | grep 'Model' |
            sed 's/Model: //g'
        ;;
        -oui)
            [ ! -z "$(echo $2 | grep -Ewo '(([0-9a-f]){2}:){2}([0-9a-f]){2}' )" ] && {

                OUI=$( echo $2 | tr ':' '-' )
                wget 'http://standards.ieee.org/cgi-bin/ouisearch' \
                    --post-data="x=${OUI}&submit2=search%21" --no-verbose -O - |
                sed '/<pre>/,/<\/pre>/ s/^/--/g' |
                grep '^--' |
                sed 's/^--//g' |
                html2text
            } || {
                iw ${iFace} scan -u |
                grep -E '^BSS|SSID|OUI|Model:'
            }
        ;;
        -mac)
            [ ! -z "$(echo $2 | grep -Ewo '(([0-9a-fA-F]){2}:){5}([0-9a-fA-F]){2}' )" ] && {
                MACTMP=$(mktemp)
                MAC="$2"
                wget "http://www.macvendorlookup.com/ouisearch?mac=${MAC}" -O - &> ${MACTMP}
                MACPROD="$(cat ${MACTMP} | tr \: \\n |
                grep -A 1 -i 'company' |
                tail -1 |
                cut -d\" -f2)"

                [ -z "${MACPROD}" ] && echo "No Vendor Exists" ||
                    echo "${MACPROD}"

                rm ${MACTMP}
            }
        ;;
        -wps)
            iw ${iFace} scan |
            grep -E '^BSS|WPS|: channel ([0-9]){1,2}' |
            sed -e 's/: chanell//' |
            tr \\n ' ' |
            sed -re "s/BSS/\n/g; s/(\(on ${iFace}\)|DS Parameter set: channel|\* Version: |-- associated|:\t)//g" |
            grep 'WPS'

        ;;
        *)
            iw ${iFace} scan |
            grep -E '^BSS|signal|SSID|: channel ([0-9]){1,2}' |
            sed -r 's/dBm|signal|SSID|\-\- associated|DS Parameter set|channel//g' |
            tr \\n ' ' | sed 's/BSS/\n/g' |
            sed "s/(on ${iFace})//" |
            awk '{print $NF,'\t',$0 }' |
            sed -r 's/:  ([0-9]){1,2}//g; s/([\ |\t]){2,}/_/g; s/_/\t/g'
            echo
        ;;
    esac
}

bh_ip2geo()
{
    [ $# -eq 0 -o "$1" == '-h' ] && return 1

    wget -q -T 30 "http://xml.utrace.de/?query=$1" -O - |
	        sed -e '4d; s/<[^>]*>//g; s/\t//g; /^$/d' |
	        tr \\n ' '
            echo
}

bh_myip()
{
    [ "$1" == '-h' ] && return 1

    wget -q -T 10 'www.mentebinaria.com.br/ext/ip.php' -O -
    echo
}

bh_ip2bin()
{
    local sIp="$(echo $1 |
                grep -Eo '^(([0-9]){1,3}\.){3}([0-9]){1,3}$')"

    [ $# -eq 0 -o -z "${sIp}" ] && return 1

    local i
	for i in $(echo "${sIp}" | tr . ' '); do
	    printf "%.8d." $(bh_dec2bin $i)
    done | sed "s/.$/\\n/"
}

bh_wgetr()
{
	[ "$1" ] || return
	local ua='Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0'
	wget -crw $((($RANDOM%10)+1)) --user-agent "$ua" "$1"
}

bh_hostcalc()
{
    local iCidr
    local iTotalHost

    bh_isdigit $1

    [ $? -eq 0 \
        -a $1 -le 30 \
        -a $1 -ge 2 ] || return 1

    iCidr=$1
    iTotalHost=$(bh_pow 2 $((32-iCidr)))
    echo ${iTotalHost} - 2 | bc
}

bh_hashes()
{
	IFS=
	[ -n "$1" ] || return
	for i in $*; do
		md5sum "$i"
		sha1sum "$i"
		sha256sum "$i"
	done
}

bh_md5rename()
{
	IFS=
	local md5_hash=
	local i=

	[ -n "$1" ] || return

	if which -s md5sum; then
		for i in $*; do
			md5_hash=$(md5sum "$i" | cut -d' ' -f1)
			mv "$i" $md5_hash
		done
	elif which -s md5; then
		for i in $*; do
			md5_hash=$(md5 "$i" | cut -d= -f2 | tr -d ' ')
			mv "$i" $md5_hash
		done
	fi
}

bh_bkp() {
	cp "$1"{,.$(date +%Y%m%d)};
}

bh_findmime()
{
	local dir=.
	local filetype
	local opt
	local matches

	[ -d "$2" ] && dir="$2"

	case $1 in
		'-txt')
			opt='text/';;
		'-zip')
			opt='application/zip';;
		'-exe')
			opt='application/x-dosexec';;
		'-msi')
			opt='application/vnd.ms-office';;
		*)
			return
	esac

	# buffering results
	matches=$(for i in "$dir"/*; do
		filetype=$(file -Nb --mime-type "$i")
		[[ "$filetype" =~ "$opt" ]] && echo "${i#./*}"
	done)

	[ -n "$matches" ] && echo "$matches"
}

bh_zipmal()
{
	[ -n "$1" ] || return
	local name=${1%\.*}.zip
	zip --encrypt -P virus "$name" $@
	ls -lh "$name"
}

bh_websearch()
{
    local i                     # count for() pagination
    local TYPE                  # type {mail,file,phone...}
    local DOMAIN                # domainame
    local TOPAGE=50             # set default pagination
    local TMP="$(mktemp)"       # tmp file, store search
    local AGENT="Mozilla/5.0"   # user agent browser default
    local SEARCH                # variable to store rearch and submit google page
    local EXTENSION             # variable to store filetype as to search for file
    local EXTRACT               # variable with regular expression to extract data/information
    local STRING=""             #
    local DOWNLOAD=0            # set donwload all file - default no
    OPTIND=0                    # getopts no crazy

    # run param
    while getopts ":g:t:s:d:e:p:" o
    do
        case "${o}" in
            g) DOWNLOAD=1
            ;;
            t) TYPE=${OPTARG}
            ;;
            p)
                if $(bh_isdigit ${OPTARG}) ; then
                    TOPAGE=$(echo 10*${OPTARG} | bc )
                else
                    TOPAGE=50
                fi
            ;;
            d) DOMAIN=${OPTARG}
            ;;
            s)
                [ ! -z "$(echo "$*" | grep "t free")" ] &&
                    STRING="$OPTARG" ||
                        STRING="intext:${OPTARG}"
            ;;
            e) EXTENSION=${OPTARG}
            ;;
        esac
    done

    [ -z "${TYPE}" ] && return 1

    case "${TYPE}" in
        mail|phone|file)
            [ -z "${DOMAIN}" ] && {
                echo "Domain is required to type ${TYPE}"
                return 1
            }
            ;;
    esac

    [ "${TYPE}" == "mail" ] && {
        SEARCH="%22@${DOMAIN}%22"
        EXTRACT="sed -e 's/<[^>]*>//g' |
                grep -Ewo '([A-Za-z0-9_\.\-]){1,}\@${DOMAIN}' "
    }

    [ "${TYPE}" == "file" -a ! -z "${EXTENSION}" ] && {
        SEARCH="site:${DOMAIN}%20filetype:${EXTENSION}%20${STRING}"
        EXTRACT="tr '<' '\n' |
                grep -Ewo 'a href=\".*' |
                grep -Ev \"(google|search)\" |
                sed 's/a href=\"//g;s/&amp;sa//g' |
                grep '/url' |
                cut -d'=' -f2"
    }

    [ "${TYPE}" == "phone" ] && {
        SEARCH="site:${DOMAIN}%20(contato|faleconosco|telefone|telephone|phone|contact)"
        EXTRACT="grep -Ewo '(\(([0xx|0-9]){2,3}\)|([0-9]){2,3}).([0-9]){3,4}.([0-9]){4,5}' "
    }

    # free
    [ "${TYPE}" == "free" -a ! -z "${STRING}" ] && {
        SEARCH="$(echo "${STRING}"|sed 's/^intext://')"
        EXTRACT="tr '<' '\n' |
                grep -Ewo 'a href=\".*' |
                grep -Ev \"(google|search)\" |
                sed 's/a href=\"//g;s/&amp;sa//g' |
                grep '/url' |
                cut -d'=' -f2"
    }
    [ -z "${SEARCH}" ] && return 1

    echo "[ ${TYPE} ] IN ${DOMAIN} ${EXTENSION}"

    for (( i=0 ; i<=${TOPAGE} ; i+=10 ))
    do
        echo "[+] ${i}"
        wget -q -T 30 -U "${AGENT}" -O - \
            "http://www.google.com.br/search?q=${SEARCH}&btnG=&start=${i}" &> ${TMP}
    done

    echo "============================================="

    [ ${DOWNLOAD} -eq 1 -a ${TYPE} == 'file' ] && {
        # tmp file store list
        LISTTMP=$(mktemp)
        # directory does not exist create it
        [ ! -d "${DOMAIN}" ] &&
            mkdir "${DOMAIN}"

        #
        cat ${TMP} | eval ${EXTRACT} | sort -u > ${LISTTMP}
        echo "Iniciando Download de $( cat ${LISTTMP} | wc -l ) Arquivos"
        # if elements exist - download
        [ $( wc -l ${LISTTMP} | cut -d" " -f1 ) -gt 0 ] &&
                wget -P "${DOMAIN}" -i ${LISTTMP} &>/dev/null
        [ $? -eq 0 ] &&
            echo "Download feito em ${DOMAIN}"

        rm -f ${LISTTMP}
    } || {
        # just list on then screen
        cat ${TMP} | eval ${EXTRACT} | sort -u
    }

    rm -rf ${TMP}
}

bashacks()
{
    echo "use -> man bashacks"
}

bashacks_depinstall()
{
    [ ${EUID} -eq 0 ] && {
        local sPktManager
        local sPkt='gcc make html2text iw nasm gdb wget'
        local sPathFile
        local sPwd=$(pwd)
        local sUdis=$(which udisks)

        # debian family
        [ -e '/etc/debian_version' ] &&
            sPktManager="apt-get install -y -qq"
        # OpenSuSE
        [ -e '/etc/SuSE-release' ] &&
            sPktManager="zypper -q --non-interactive install"
        # centos, fedora or redhat
        [ -e '/etc/redhat-release' -o \
            -e '/etc/centos-release' -o \
            -e '/etc/fedora-release' ] &&
            sPktManager="yum -q -y install"

        echo '[ Dep install ] ...'
        ${sPktManager} ${sPkt}

        [ -z "${sUdis}" ] && {
            cd /tmp
            echo '[ Download udis86 ] ...'

            # prevent corrupt file
            [ -e '/tmp/download' ] &&
                rm /tmp/download

            wget http://sourceforge.net/projects/udis86/files/latest/download &> /dev/null
            tar -xf /tmp/download
            sPathFile=$(ls -1 | grep 'udis86')
            cd ${sPathFile}
            ./configure &&
                make &&
                make install &&
                    cd udcli &&
                        make &&
                        make install
        } || echo "[ udis86 already installed on the system ]"

        [ $? -eq 0 ] && {
            echo
            echo -n '=====    [ OK ]'
            echo
            cd ${sPwd}
            return 0
        }
    } || echo "root is required"
    return 1
}

bh_checkdir() { test -d $bh_cache || mkdir -p $bh_cache; }

bh_user_path="$HOME/.config/bashacks"
bh_cache="$bh_user_path/cache/asm"

bh_str2hex()
{
    [ $# -eq 0 ] && return 1

	case "$1" in
		"-s")
			echo -n "$2" | hexdump -ve '/1 "%02x"' | sed 's/^/0x/'
			echo
			;;
		"-x")
			echo -n "$2" | hexdump -ve '/1 "%02x"' | sed 's/../\\x&/g'
			echo
			;;
		"-0x")
			echo -n "$2" | hexdump -ve '/1 "0x%02x "' | sed 's/\(.*\) /\1/'
			echo
			;;
		"-c")
			echo -n '{'
			echo -n "$2" | hexdump -ve '/1 "0x%02x, "' | sed 's/\(.*\), /\1/'
			echo '}'
			;;
        *)
			echo -n "$1" | hexdump -ve '/1 "%02x "' | sed 's/\(.*\) /\1/'
			echo
			;;
	esac
}

bh_isdigit()
{
    [ $# -ne 1 ] && return 1

    echo "$1" | grep -Eqw '^[0-9]+$'
}

bh_str2hexr()
{
    [ $# -eq 0 ] && return 1

    case "$1" in
	    "-x" | "-0x" | "-c" | "-s")
	        bh_str2hex $1 "$(echo "$2" | rev)"
		;;
        *)
		    bh_str2hex "$(echo "$1" | rev)"
	    ;;
	esac
}

bh_islower()
{
   [ $# -eq 0 ] && return 1

   echo "$1" | grep -Eqw '^[a-z]+$'
}

bh_isspace()
{
    local str="$(echo $1 |
        hexdump -ve '/1 "%02x"'|
        sed 's/../x& /g' )"
    for h in $str;
    do
        case $h in
            x09|x0a|x0b|x0c|x0d|x20) return 0
                ;;
            *) return 1
                ;;
        esac
    done
}

bh_isgraph()
{
    local char_in="$1"

    # dec 33 - 126

    [ "${#char_in}" -gt 2 ] && return 1

    [ $(bh_asc2dec "${char_in}") -ge 33 -a \
        $(bh_asc2dec "${char_in}") -le 126 ] &&
        return 0

    return 1
}

bh_urlencode(){
	[ $# -ne 1 ] && return 1;
	echo -ne "$1" | perl -pe 's/\W/"%".unpack "H*",$&/gei'
	echo
}


bh_asciitable()
{
	echo -en \
	"Dec Hex    Dec Hex    Dec Hex  Dec Hex  Dec Hex  Dec Hex   Dec Hex   Dec Hex\n\
  0 00 NUL  16 10 DLE  32 20    48 30 0  64 40 @  80 50 P   96 60 \`  112 70 p\n\
  1 01 SOH  17 11 DC1  33 21 !  49 31 1  65 41 A  81 51 Q   97 61 a  113 71 q\n\
  2 02 STX  18 12 DC2  34 22 \"  50 32 2  66 42 B  82 52 R   98 62 b  114 72 r\n\
  3 03 ETX  19 13 DC3  35 23 #  51 33 3  67 43 C  83 53 S   99 63 c  115 73 s\n\
  4 04 EOT  20 14 DC4  36 24 $  52 34 4  68 44 D  84 54 T  100 64 d  116 74 t\n\
  5 05 ENQ  21 15 NAK  37 25 %  53 35 5  69 45 E  85 55 U  101 65 e  117 75 u\n\
  6 06 ACK  22 16 SYN  38 26 &  54 36 6  70 46 F  86 56 V  102 66 f  118 76 v\n\
  7 07 BEL  23 17 ETB  39 27 '  55 37 7  71 47 G  87 57 W  103 67 g  119 77 w\n\
  8 08 BS   24 18 CAN  40 28 (  56 38 8  72 48 H  88 58 X  104 68 h  120 78 x\n\
  9 09 HT   25 19 EM   41 29 )  57 39 9  73 49 I  89 59 Y  105 69 i  121 79 y\n\
 10 0A LF   26 1A SUB  42 2A *  58 3A :  74 4A J  90 5A Z  106 6A j  122 7A z\n\
 11 0B VT   27 1B ESC  43 2B +  59 3B ;  75 4B K  91 5B [  107 6B k  123 7B {\n\
 12 0C FF   28 1C FS   44 2C ,  60 3C <  76 4C L  92 5C \\  108 6C l  124 7C |\n\
 13 0D CR   29 1D GS   45 2D -  61 3D =  77 4D M  93 5D ]  109 6D m  125 7D }\n\
 14 0E SO   30 1E RS   46 2E .  62 3E >  78 4E N  94 5E ^  110 6E n  126 7E ~\n\
 15 0F SI   31 1F US   47 2F /  63 3F ?  79 4F O  95 5F _  111 6F o  127 7F DEL\n"
}

bh_iscntrl() {
    local iCHAR=$(bh_asc2dec "$1")
    [ $iCHAR -le 31 -o \
        $iCHAR -eq 127 ] && return 0 ||
            return 1
}

bh_isprint()
{
	# nao ta rolando
	local i

	for i in $(bh_str2hex -0x "$1" | sed 's/\(....\)/\1 /g'); do
		[ $(($i)) -ge 32 -a $(($i)) -le 127 ] || return 1
	done
	return 0
}

bh_ispunct() {
   if $(bh_isgraph "$1")
   then
      if ! $(bh_isalnum "$1")
      then
         return 0
      fi
   else
      return 1
   fi
   return 1
}

bh_isalpha()
{
    [ $# -ne 1 ] && return 1

    echo "$1" | grep -Eqw '^[A-Za-z]+$'
}

bh_utf8table()
{
	echo -en \
"Hex      Hex      Hex      Hex      Hex      Hex      Hex      Hex\n\
c2 a0    c2 ac ¬  c2 b8 ¸  c3 84 Ä  c3 90 Ð  c3 9c Ü  c3 a8 è  c3 b4 ô\n\
c2 a1 ¡  c2 ad ­  c2 b9 ¹  c3 85 Å  c3 91 Ñ  c3 9d Ý  c3 a9 é  c3 b5 õ\n\
c2 a2 ¢  c2 ae ®  c2 ba º  c3 86 Æ  c3 92 Ò  c3 9e Þ  c3 aa ê  c3 b6 ö\n\
c2 a3 £  c2 af ¯  c2 bb »  c3 87 Ç  c3 93 Ó  c3 9f ß  c3 ab ë  c3 b7 ÷\n\
c2 a4 ¤  c2 b0 °  c2 bc ¼  c3 88 È  c3 94 Ô  c3 a0 à  c3 ac ì  c3 b8 ø\n\
c2 a5 ¥  c2 b1 ±  c2 bd ½  c3 89 É  c3 95 Õ  c3 a1 á  c3 ad í  c3 b9 ù\n\
c2 a6 ¦  c2 b2 ²  c2 be ¾  c3 8a Ê  c3 96 Ö  c3 a2 â  c3 ae î  c3 ba ú\n\
c2 a7 §  c2 b3 ³  c2 bf ¿  c3 8b Ë  c3 97 ×  c3 a3 ã  c3 af ï  c3 bb û\n\
c2 a8 ¨  c2 b4 ´  c3 80 À  c3 8c Ì  c3 98 Ø  c3 a4 ä  c3 b0 ð  c3 bc ü\n\
c2 a9 ©  c2 b5 µ  c3 81 Á  c3 8d Í  c3 99 Ù  c3 a5 å  c3 b1 ñ  c3 bd ý\n\
c2 aa ª  c2 b6 ¶  c3 82 Â  c3 8e Î  c3 9a Ú  c3 a6 æ  c3 b2 ò  c3 be þ\n\
c2 ab «  c2 b7 ·  c3 83 Ã  c3 8f Ï  c3 9b Û  c3 a7 ç  c3 b3 ó  c3 bf ÿ\n"
}

bh_isascii() {
   local c2d=$(bh_asc2dec "1")

   if $(bh_isdigit $c2d)
   then
      [ $c2d -lt 127 \
         -a $c2d -gt 0 ] &&
         return 0 ||
         return 1
   fi
   return 1
}

bh_hex2str()
{
    [ $# -ne 1 ] && return 1

    local hex
    local str
    local i

    hex=$(echo $1 | sed 's/\(0x\|\\x\| \|{\|}\|,\)//g')

    # insert a space each two chars
    hex=$(echo $hex | sed 's/../& /g')

    # prefix with \x, needed by echo
    for i in $hex; do
    	str="$str\\x$i"
    done

    echo -e $str
}

bh_asc2dec()
{
    [ $# -ne 1 ] && return 1

    printf "%d\n" "'$1"
}

bh_isalnum()
{
    [ $# -ne 1 ] && return 1

    echo "$1" | grep -Eqw '^[0-9A-Za-z]+$'
}

bh_isupper()
{
    [ $# -ne 1 ] && return 1

    echo "$1" | grep -Eqw '^[A-Z]+$'
}

bh_urldecode(){
	[ $# -ne 1 ] && return 1
	echo "$1" | perl -pe 's/%([0-9a-f]{2})/pack "H*", $1/gie'
}


bh_dec2asc()
{
    [ $# -ne 1 ] && return 1

    echo -e $(printf "\\\x%x" $1)
}

bh_isxdigit()
{
    [ $# -ne 1 ] && return 1

    echo "$1" | grep -Eqw '^[0-9A-Fa-f]+$'
}

bh_raffle()
{
	local i
	local interval=3
	test -n "$3" && interval=$3
	for i in $(seq $1 $2 | sort -R); do
		echo $i
		sleep $interval;
	done
}

bh_matrix()
{
	echo -e "\e[32m";
	while :; do
		printf '%*c' $(($RANDOM % 30)) $(($RANDOM % 2));
	done
}

