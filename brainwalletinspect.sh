#!/bin/bash

#
# Bitcoin Brain wallet inspector v0.00000001 by Daniél Riveiro (daniel@riveiro.com).
#
# Credits to https://github.com/grondilu/bitcoin-bash-tools for various functions.
#
# Requires "dc", the unix desktop calculator (which should be included in the 'bc' package)
#

# Default
_VERBOSE=0

#
# Show app head
#
showAppHead()
{
    echo "Bitcoin brain wallet inspector v0.00000001"
}

#
# Show app help
#
showAppHelp()
{
    showAppHead
    echo "Usage: brainwalletinspect [-pv]"
    echo "  --password|-p <arg>  Brain wallet password in clear text"
    echo "  --verbose|-v         Verbose output"
    echo ""
    echo "Known brain wallets are: sausage, fuckyou"
}

#
# Inspect brain wallet
#
brainWalletInspect()
{
    showAppHead
    echo "Inspecting brain wallet: ${1}"
    declare -a base58=(
          1 2 3 4 5 6 7 8 9
        A B C D E F G H   J K L M N   P Q R S T U V W X Y Z
        a b c d e f g h i j k   m n o p q r s t u v w x y z
    )
    unset dcr; for i in {0..57}; do dcr+="${i}s${base58[i]}"; done
    declare ec_dc='
    I16i7sb0sa[[_1*lm1-*lm%q]Std0>tlm%Lts#]s%[Smddl%x-lm/rl%xLms#]s~
    483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    2 100^d14551231950B75FC4402DA1732FC9BEBF-so1000003D1-ddspsm*+sGi
    [_1*l%x]s_[+l%x]s+[*l%x]s*[-l%x]s-[l%xsclmsd1su0sv0sr1st[q]SQ[lc
    0=Qldlcl~xlcsdscsqlrlqlu*-ltlqlv*-lulvstsrsvsulXx]dSXxLXs#LQs#lr
    l%x]sI[lpSm[+q]S0d0=0lpl~xsydsxd*3*lal+x2ly*lIx*l%xdsld*2lx*l-xd
    lxrl-xlll*xlyl-xrlp*+Lms#L0s#]sD[lpSm[+q]S0[2;AlDxq]Sdd0=0rd0=0d
    2:Alp~1:A0:Ad2:Blp~1:B0:B2;A2;B=d[0q]Sx2;A0;B1;Bl_xrlm*+=x0;A0;B
    l-xlIxdsi1;A1;Bl-xl*xdsld*0;Al-x0;Bl-xd0;Arl-xlll*x1;Al-xrlp*+L0
    s#Lds#Lxs#Lms#]sA[rs.0r[rl.lAxr]SP[q]sQ[d0!<Qd2%1=P2/l.lDxs.lLx]
    dSLxs#LPs#LQs#]sM[lpd1+4/r|]sR
    ';

    #
    # Password
    #
    PASSWORD=$1
    echo "  Password (clear text):                                ${PASSWORD}"

    #
    # Compute BTC private key
    #
    PASSWORD_SHA256=`echo -n "${PASSWORD}" | sha256sum | awk '{print $1}'`
    echo "  Password (SHA-256):                                   $PASSWORD_SHA256"

    PASSWORD_SHA256_EXT="80${PASSWORD_SHA256}"
    echo "  Password (SHA-256 extended):                          $PASSWORD_SHA256_EXT"

    PASSWORD_SHA256_EXT_SHA256=`echo -n "${PASSWORD_SHA256_EXT}" | xxd -r -p | sha256sum -b | awk '{print $1}'`
    echo "  Password (SHA-256 extended + SHA-256):                $PASSWORD_SHA256_EXT_SHA256"

    PASSWORD_SHA256_EXT_SHA256_CHECKSUM=`echo -n "${PASSWORD_SHA256_EXT_SHA256}" | xxd -r -p | sha256sum -b | awk '{print $1}'`
    echo "  Password checksum (SHA-256 extended + SHA256):        $PASSWORD_SHA256_EXT_SHA256_CHECKSUM"

    PASSWORD_SHA256_EXT_SHA256_CHECKSUM_HEAD=`echo -n "${PASSWORD_SHA256_EXT_SHA256_CHECKSUM}" | cut -b -8`
    echo "  Password checksum head (SHA-256 extended + SHA-256):  $PASSWORD_SHA256_EXT_SHA256_CHECKSUM_HEAD"

    PRIVATE_KEY_BASE16="${PASSWORD_SHA256_EXT}${PASSWORD_SHA256_EXT_SHA256_CHECKSUM_HEAD}"
    echo "  Private key (base-16):                                $PRIVATE_KEY_BASE16"

    encodeBase58() {
        dc -e "16i ${1^^} [3A ~r d0<x]dsxx +f" |
        while read -r n; do echo -n "${base58[n]}"; done
    }
    PRIVATE_KEY_BASE58=`encodeBase58 $PRIVATE_KEY_BASE16`
    echo "  Private key (base-58):                                ${PRIVATE_KEY_BASE58}"

    #
    # Compute BTC address
    #
    SECRET_EXPONENT="${PASSWORD_SHA256}"
    echo "  Secret exponent:                                      ${SECRET_EXPONENT}"

    checksum() {
        perl -we "print pack 'H*', '$1'" |
        openssl dgst -sha256 -binary |
        openssl dgst -sha256 -binary |
        perl -we "print unpack 'H8', join '', <>"
    }
    hexToAddress() {
        local version=${2:-00} x="$(printf "%${3:-40}s" $1 | sed 's/ /0/g')"
        printf "%34s\n" "$(encodeBase58 "$version$x$(checksum "$version$x")")" |
        {
        if ((version == 0))
        then sed -r 's/ +/1/'
        else cat
        fi
        }
    }
    hash160() {
        openssl dgst -sha256 -binary |
        openssl dgst -rmd160 -binary |
        perl -we "print unpack 'H*', join '', <>"
    }

    PUBLIC_KEY_X_AND_Y=`dc -e "$ec_dc lG I16i${SECRET_EXPONENT^^}ri lMx 16olm~ n[ ]nn"`
    #echo "  Public keys (Y & X):                                  ${PUBLIC_KEY_X_AND_Y}"

    PUBLIC_KEY_X=`echo ${PUBLIC_KEY_X_AND_Y} | awk '{print $2}'`
    echo "  Public key (X):                                       ${PUBLIC_KEY_X}"

    PUBLIC_KEY_Y=`echo ${PUBLIC_KEY_X_AND_Y} | awk '{print $1}'`
    echo "  Public key (Y):                                       ${PUBLIC_KEY_Y}"

    WIF_COMPRESSED="$(hexToAddress "${SECRET_EXPONENT}01" 80 66)"
    echo "  WIF compressed:                                       ${WIF_COMPRESSED}"

    WIF_UNCOMPRESSED="$(hexToAddress "${SECRET_EXPONENT}" 80 64)"
    echo "  WIF uncompressed:                                     ${WIF_UNCOMPRESSED}"

    if [[ "$PUBLIC_KEY_Y" =~ [02468ACE]$ ]]
    then y_parity="02"
    else y_parity="03"
    fi
    ADDRESS_COMPRESSED="$(hexToAddress "$(perl -e "print pack q(H*), q($y_parity$PUBLIC_KEY_X)" | hash160)")"
    echo "  Address compressed:                                   ${ADDRESS_COMPRESSED}"

    ADDRESS_UNCOMPRESSED="$(hexToAddress "$(perl -e "print pack q(H*), q(04$PUBLIC_KEY_X$PUBLIC_KEY_Y)" | hash160)")"
    echo "  Address uncompressed:                                 ${ADDRESS_UNCOMPRESSED}"

    #
    # Transactions
    #
    echo ""
    echo "Transactions:"
    BTC_RECEIVED=`GET http://blockexplorer.com/q/getreceivedbyaddress/${ADDRESS_UNCOMPRESSED}`
    echo "  Recieved (BTC):                                       ${BTC_RECEIVED}"
    BTC_BALANCE=`GET http://blockexplorer.com/q/addressbalance/${ADDRESS_UNCOMPRESSED}`
    echo "  Balance (BTC):                                        ${BTC_BALANCE}"
}

#
# Parse command-line arguments
#
while getopts "h?vp:" opt; do
    case "$opt" in
    h|\?)
        showAppHelp
        exit 0
        ;;
    v)
        _VERBOSE=1
        ;;
    p)
        brainWalletInspect $OPTARG
        ;;
    esac
done
