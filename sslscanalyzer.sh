#!/bin/bash
# sslscanalyzer.sh
# 1/23/2015 by Ted R (http://github.com/actuated)
# Script to take an a file containing multiple sslscan results, and parse them for a summary table of findings
varDateCreated="1/23/2015"
varDateLastMod="1/25/2016"
# Revised report options, replaced them with single -r option.

# NOTE - Weak ciphers currently identified with: grep -E 'SSLv2|SSLv3| 0 bits| 40 bits| 56 bits| 112 bits|RC4|AECDH|ADH'

# Create temporary directory for processing
varYMDHMS=$(date +%F-%H-%M-%S)
varTemp="ssls-temp-$varYMDHMS"
if [ -e "$varTemp" ]; then rm -r "$varTemp"; fi
# Set name for HTML output file
varYMDHM=$(date +%F-%H-%M)
varOutFile="sslscanalyzer-$varYMDHM.html"
# Default values for options
varQuiet="N"
varReportMode="0"

function fnUsage {
  echo
  echo "=====================[ sslscanalyzer.sh - Ted R (github: actuated) ]====================="
  echo
  echo "Script for reading an input file containing (one or) multiple sslscan results, and making"
  echo "an HTML table to list the results in a more condensed format."
  echo  
  echo "Created $varDateCreated, last modified $varDateLastMod."
  echo
  echo "========================================[ usage ]========================================"
  echo
  echo "./sslscanalyzer.sh [input file] [options]"
  echo
  echo "[input file]   Your input file. Required."
  echo
  echo "-h             Displays this help/usage information."
  echo
  echo "-q             Optional 'quiet' switch. Disables pause for confirmation at the start of"
  echo "               the script, as well as the option to open the output file at the end."
  echo
  echo "-r [value]     Report format options. See details below for supported values."
  echo
  echo "===================================[ report settings ]==================================="
  echo
  echo "Standard: Information combined and categorized into 3 columns for each host, including:"
  echo "(1) SSL Server Checks - Session Renegotiation, Compression, and Heartbleed."
  echo "(2) Weak/accepted ciphers."
  echo "(3) Certificate - Subject, Issuer, Signature Algorithm, Key Space, and Expiration."
  echo
  echo "Full: Columns are not combined, each value has its own column."
  echo
  echo "Values for -r:"
  echo
  echo " 0  Default. Standard report with Yes/No summary for weak ciphers."
  echo " 1  Standard report with all accepted weak ciphers listed."
  echo " 2  Standard report with all accepted ciphers listed."
  echo " 3  Full report with Yes/No summary for weak ciphers."
  echo " 4  Full report with all accepted weak ciphers listed."
  echo " 5  Full report with all accepted ciphers listed."
  echo
  exit
}

function fnProcessInFile {

  echo -n "Processing input file..."

  # Sanitize input file to remove sslscan color coding if necessary
  cat -A "$varInFile" | tr -d '\$' | sed 's/\^\[\[0m//g' | sed 's/\^\[\[31m//g' | sed 's/\^\[\[32m//g'| sed 's/\^\[\[33m//g'| sed 's/\^\[\[1\;34m//g' | sed 's/\^\[\[35m//g' | sed 's/\^\[\[41m//g'  > $varTemp/InFile.txt
  varCleanInFile="$varTemp/InFile.txt"
  varParsed="$varTemp/parsed.txt"
  varUnsortedHosts="$varTemp/unsorted-hosts.txt"
  
  # Parse clean input file
  while read varLine; do

    varLastHost="$varHost"
    varHost=$(echo "$varLine" | grep 'Testing SSL server' | awk '{print $4 ":" $7}')
    if [ "$varHost" = "" ]; then varHost="$varLastHost"; fi
    if [ "$varHost" != "$varLastHost" ]; then echo "$varHost" >> "$varUnsortedHosts"; echo -n "."; fi

    varCheckSessionRenegotiation=$(echo "$varLine" | grep -i 'session renegotiation')
    if [ "$varCheckSessionRenegotiation" != "" ]; then
      echo "$varHost,grep1SessionRenegotiation,$varCheckSessionRenegotiation" >> "$varParsed"
    fi

    varCheckCompression=$(echo "$varLine" | grep '^Compression ')
    if [ "$varCheckCompression" != "" ]; then
      echo "$varHost,grep2Compression,$varCheckCompression" >> "$varParsed"
    fi

    varCheckHeartbleed=$(echo "$varLine" | grep 'vulnerable to heartbleed')
    if [ "$varCheckHeartbleed" != "" ]; then
      echo "$varHost,grep3Heartbleed,$varCheckHeartbleed" >> "$varParsed"
    fi

    varCheckCiphers=$(echo "$varLine" | grep '^Accepted')
    if [ "$varCheckCiphers" != "" ]; then
      if [ "$varDoCiphers" = "ALL" ] || [ "$varDoCiphers" = "SUMMARY" ]; then
        varCiphers=$(echo "$varCheckCiphers" | awk '{print $2,"-",$3,$4,"-",$5}')
        echo "$varHost,grep4Ciphers,$varCiphers" >> "$varParsed"
      elif [ "$varDoCiphers" = "WEAK" ]; then
        varCiphers=$(echo "$varCheckCiphers" | grep -E 'SSLv2|SSLv3| 0 bits| 40 bits| 56 bits| 112 bits|RC4|AECDH|ADH' | awk '{print $2,"-",$3,$4,"-",$5}')
        if [ "$varCiphers" != "" ]; then 
          echo "$varHost,grep4Ciphers,$varCiphers" >> "$varParsed"
        fi
      fi
    fi

    varCheckIssuers=$(echo "$varLine" | grep '^Issuer:' | grep -v '=')
    if [ "$varCheckIssuers" != "" ]; then
      varIssuer=$(echo "$varCheckIssuers" | awk '{$1=""; print $0}' | sed -e 's/^[ \t]*//')
      echo "$varHost,grep5Issuer,$varIssuer" >> "$varParsed"
    fi

    varCheckSignatureAlgorithm=$(echo "$varLine" | grep '^Signature Algorithm:')
    if [ "$varCheckSignatureAlgorithm" != "" ]; then
      varSignatureAlgorithm=$(echo "$varCheckSignatureAlgorithm" | awk '{print $3}')
      echo "$varHost,grep6SignatureAlgorithm,$varSignatureAlgorithm" >> "$varParsed"
    fi

    varCheckRSAKeyStrength=$(echo "$varLine" | grep '^RSA Key Strength:')
    if [ "$varCheckRSAKeyStrength" != "" ]; then
      varRSAKeyStrength=$(echo "$varCheckRSAKeyStrength" | awk '{print $4}')
      echo "$varHost,grep7RSAKeyStrength,$varRSAKeyStrength" >> "$varParsed"
    fi

    varCheckExpiration=$(echo "$varLine" | grep 'Not valid after:')
    if [ "$varCheckExpiration" != "" ]; then
      varExpiration=$(echo "$varCheckExpiration" | awk '{print $4, $5, $6, $7}')
      echo "$varHost,grep8Expiration,$varExpiration" >> "$varParsed"
    fi

    varCheckSubject=$(echo "$varLine" | grep '^Subject:' | grep -v '=')
    if [ "$varCheckSubject" != "" ]; then
      varSubject=$(echo "$varCheckSubject" | awk '{print $2}')
      echo "$varHost,grep9Subject,$varSubject" >> "$varParsed"
    fi

  done < "$varCleanInFile"

  if [ -f "$varParsed" ]; then
    varSorted="$varTemp/sorted.txt"
    cat "$varParsed" | sort -V | uniq > "$varSorted"
  fi

  if [ -f "$varUnsortedHosts" ]; then
    varSortedHosts="$varTemp/sorted-hosts.txt"
    cat "$varUnsortedHosts" | sort -V | uniq > "$varSortedHosts"
  fi

  echo " Done."

}

function fnHTMLHead {
  echo "  <head>" >> "$varOutFile"
  echo "    <title>sslscanalyzer.sh - Ted R (github: actuated)</title>" >> "$varOutFile"
  echo "    <style>" >> "$varOutFile"
  echo "      table, td {border: 2px solid black;" >> "$varOutFile"
  echo "        border-collapse: collapse;}" >> "$varOutFile"
  echo "      td {font-family: verdana, sans-serif;" >> "$varOutFile"
  echo "        vertical-align: top;" >> "$varOutFile"
  echo "        font-size: small;}" >> "$varOutFile"
  echo "      td.heading {background-color: #3399FF;" >> "$varOutFile"
  echo "        font-weight: bold;}" >> "$varOutFile"
  echo "      a {color: #000000;}" >> "$varOutFile"
  echo "    </style>" >> "$varOutFile"
  echo "  </head>" >> "$varOutFile"
}

function fnProcessResultsFull {

  echo -n "Creating HTML report..."

  # Make sure varSorted/varSortedHosts files were created
  if [ ! -f "$varSorted" ]; then echo "Error: Couldn't parse any results from '$varInFile'."; echo; return; fi
  if [ ! -f "$varSortedHosts" ]; then echo "Error: Couldn't parse any results from '$varInFile'."; echo; return; fi

  # Write beginning of HTML file
  echo "<html>" > "$varOutFile"
  fnHTMLHead
  echo "  <body>" >> "$varOutFile"
  echo "    <table cellpadding='4'>" >> "$varOutFile"
  echo "      <tr>" >> "$varOutFile"
  echo "        <td colspan='10' class='heading'><font size='+2'><center>sslscanalyzer.sh - <a href='https://github.com/actuated' target='_blank'>Ted R (github: actuated)</a></center></font></td>" >> "$varOutFile"
  echo "      </tr>" >> "$varOutFile"
  echo "      <tr>" >> "$varOutFile"
  echo "        <td rowspan='2' class='heading'>Host</td>" >> "$varOutFile"
  echo "        <td colspan='4' class='heading'>SSL Server</td>" >> "$varOutFile"
  echo "        <td colspan='5' class='heading'>Certificate</td>" >> "$varOutFile"
  echo "      </tr>" >> "$varOutFile"
  echo "      <tr>" >> "$varOutFile"
  echo "        <td class='heading'>Session Renegotiation</td>" >> "$varOutFile"
  echo "        <td class='heading'>Compression</td>" >> "$varOutFile"
  echo "        <td class='heading'>Heartbleed</td>" >> "$varOutFile"
  echo "        <td class='heading'>$varCipherText</td>" >> "$varOutFile"
  echo "        <td class='heading'>Subject</td>" >> "$varOutFile"
  echo "        <td class='heading'>Issuer</td>" >> "$varOutFile"
  echo "        <td class='heading'>Signature Algorithm</td>" >> "$varOutFile"
  echo "        <td class='heading'>Key Strength</td>" >> "$varOutFile"
  echo "        <td class='heading'>Expiration</td>" >> "$varOutFile"
  echo "      </tr>" >> "$varOutFile"

  # Process results for each host
  while read varThisHost; do

    echo -n "."

    echo "      <tr>" >> "$varOutFile"

    # Table Cell: Host/Port
    echo "        <td>" >> "$varOutFile"
    varThisHostAddr=$(echo "$varThisHost" | awk -F ":" '{print $1}')
    varThisHostPort=$(echo "$varThisHost" | awk -F ":" '{print $2}')
    if [ "$varThisHostPort" = "443" ] || [ "$varThisHostPort" = "8443" ]; then
      echo "          <a href='https://$varThisHost' target='_blank'>$varThisHostAddr<br>Port $varThisHostPort</a>" >> "$varOutFile"
    else
      echo "          $varThisHostAddr<br>Port $varThisHostPort" >> "$varOutFile"
    fi
    echo "        </td>" >> "$varOutFile"

    # Check for session renegotion for this host
    varTestGrep1=$(grep "$varThisHost" "$varSorted" | grep 'grep1SessionRenegotiation' | wc -l)
    if [ "$varTestGrep1" = "0" ]; then
      echo "        <td></td>" >> "$varOutFile"
    else
      varGrep1=$(grep "$varThisHost" "$varSorted"| grep 'grep1SessionRenegotiation' | awk -F "," '{print $3 "<br>"}')
      echo "        <td>$varGrep1</td>" >> "$varOutFile"
    fi

    # Check for compression for this host
    varTestGrep2=$(grep "$varThisHost" "$varSorted" | grep 'grep2Compression' | wc -l)
    if [ "$varTestGrep2" = "0" ]; then
      echo "        <td></td>" >> "$varOutFile"
    else
      varGrep2=$(grep "$varThisHost" "$varSorted"| grep 'grep2Compression' | awk -F "," '{print $3 "<br>"}')
      echo "        <td>$varGrep2</td>" >> "$varOutFile"
    fi

    # Check for heartbleed for this host
    varTestGrep3=$(grep "$varThisHost" "$varSorted" | grep 'grep3Heartbleed' | wc -l)
    if [ "$varTestGrep3" = "0" ]; then
      echo "        <td></td>" >> "$varOutFile"
    else
      varGrep3=$(grep "$varThisHost" "$varSorted"| grep 'grep3Heartbleed' | awk -F "," '{print "          " "&#8226;" $3 "<br>"}')
      echo "        <td>" >> "$varOutFile"
      echo "$varGrep3" >> "$varOutFile"
      echo "        </td>" >> "$varOutFile"
    fi

    # Table Cell: Ciphers
    echo "        <td>" >> "$varOutFile"
    varTestGrep4=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | wc -l)
    if [ "$varTestGrep4" != "0" ]; then
      case "$varDoCiphers" in
        SUMMARY )
          varFlagSSLV2=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'SSLv2')
          if [ "$varFlagSSLV2" = "" ]; then
            echo "          &#8226;Any SSLv2: No<br>" >> "$varOutFile"
          else
            echo "          &#8226;Any SSLv2: Yes<br>" >> "$varOutFile"
          fi
          varFlagSSLV3=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'SSLv3')
          if [ "$varFlagSSLV3" = "" ]; then
            echo "          &#8226;Any SSLv3: No<br>" >> "$varOutFile"
          else
            echo "          &#8226;Any SSLv3: Yes<br>" >> "$varOutFile"
          fi
          varFlagTLSWeak=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'TLS' | grep -E ' 0 bits| 40 bits| 56 bits| 112 bits')
          if [ "$varFlagTLSWeak" = "" ]; then
            echo "          &#8226;TLS with &lt;128 Bit Ciphers: No<br>" >> "$varOutFile"
          else
            echo "          &#8226;TLS with &lt;128 Bit Ciphers: Yes<br>" >> "$varOutFile"
          fi
          varFlagTLSCrypto=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'TLS' | grep -E 'RC4|AECDH|ADH')
          if [ "$varFlagTLSCrypto" = "" ]; then
            echo "          &#8226;TLS with ADH, AECDH, or RC4: No<br>" >> "$varOutFile"
          else
            echo "          &#8226;TLS with ADH, AECDH, or RC4: Yes<br>" >> "$varOutFile"
          fi
          ;;
        WEAK | ALL )
          varGrep4=$(grep "$varThisHost" "$varSorted"| grep 'grep4Ciphers' | awk -F "," '{print "          " "&#8226;" $3 "<br>"}')
          echo "$varGrep4" >> "$varOutFile"
          ;;
      esac
    fi
    echo "        </td>" >> "$varOutFile"

    # Check for subject for this host
    varTestGrep9=$(grep "$varThisHost" "$varSorted" | grep 'grep9Subject' | wc -l)
    if [ "$varTestGrep9" = "0" ]; then
      echo "        <td></td>" >> "$varOutFile"
    else
      varGrep9=$(grep "$varThisHost" "$varSorted"| grep 'grep9Subject' | awk -F "," '{print $3 "<br>"}')
      echo "        <td>$varGrep9</td>" >> "$varOutFile"
    fi

    # Check for issuer for this host
    varTestGrep5=$(grep "$varThisHost" "$varSorted" | grep 'grep5Issuer' | wc -l)
    if [ "$varTestGrep5" = "0" ]; then
      echo "        <td></td>" >> "$varOutFile"
    else
      varGrep5=$(grep "$varThisHost" "$varSorted"| grep 'grep5Issuer' | awk -F "," '{print $3 "<br>"}')
      echo "        <td>$varGrep5</td>" >> "$varOutFile"
    fi

    # Check for signature algorithm for this host
    varTestGrep6=$(grep "$varThisHost" "$varSorted" | grep 'grep6SignatureAlgorithm' | wc -l)
    if [ "$varTestGrep6" = "0" ]; then
      echo "        <td></td>" >> "$varOutFile"
    else
      varGrep6=$(grep "$varThisHost" "$varSorted"| grep 'grep6SignatureAlgorithm' | awk -F "," '{print $3 "<br>"}')
      echo "        <td>$varGrep6</td>" >> "$varOutFile"
    fi

    # Check for rsa key strength for this host
    varTestGrep7=$(grep "$varThisHost" "$varSorted" | grep 'grep7RSAKeyStrength' | wc -l)
    if [ "$varTestGrep7" = "0" ]; then
      echo "        <td></td>" >> "$varOutFile"
    else
      varGrep7=$(grep "$varThisHost" "$varSorted"| grep 'grep7RSAKeyStrength' | awk -F "," '{print $3 "<br>"}')
      echo "        <td>$varGrep7</td>" >> "$varOutFile"
    fi

    # Check for expiration for this host
    varTestGrep8=$(grep "$varThisHost" "$varSorted" | grep 'grep8Expiration' | wc -l)
    if [ "$varTestGrep8" = "0" ]; then
      echo "        <td></td>" >> "$varOutFile"
    else
      varGrep8=$(grep "$varThisHost" "$varSorted"| grep 'grep8Expiration' | awk -F "," '{print $3 "<br>"}')
      echo "        <td>$varGrep8</td>" >> "$varOutFile"
    fi

    echo "      </tr>" >> "$varOutFile"
  
  done < "$varSortedHosts"

  # Write end of HTML file
  echo "    </table>" >> "$varOutFile"
  echo "  </body>" >> "$varOutFile"
  echo "</html>" >> "$varOutFile"  

  echo " Done."

}

function fnProcessResultsStd {

  echo -n "Creating HTML report..."

  # Make sure varSorted/varSortedHosts files were created
  if [ ! -f "$varSorted" ]; then echo "Error: Couldn't parse any results from '$varInFile'."; echo; return; fi
  if [ ! -f "$varSortedHosts" ]; then echo "Error: Couldn't parse any results from '$varInFile'."; echo; return; fi

  # Write beginning of HTML file
  echo "<html>" > "$varOutFile"
  fnHTMLHead
  echo "  <body>" >> "$varOutFile"
  echo "    <table cellpadding='4'>" >> "$varOutFile"
  echo "      <tr>" >> "$varOutFile"
  echo "        <td colspan='4' class='heading'><font size='+2'><center>sslscanalyzer.sh - <a href='https://github.com/actuated' target='_blank'>Ted R (github: actuated)</a></center></font></td>" >> "$varOutFile"
  echo "      </tr>" >> "$varOutFile"
  echo "      <tr>" >> "$varOutFile"
  echo "        <td class='heading'>Host</td>" >> "$varOutFile"
  echo "        <td class='heading'>SSL Server Checks</td>" >> "$varOutFile"
  echo "        <td class='heading'>SSL Server: $varCipherText</td>" >> "$varOutFile"
  echo "        <td class='heading'>Certificate</td>" >> "$varOutFile"
  echo "      </tr>" >> "$varOutFile"

  # Process results for each host
  while read varThisHost; do

    echo -n "."

    echo "      <tr>" >> "$varOutFile"

    # Table Cell: Host/Port
    echo "        <td>" >> "$varOutFile"
    varThisHostAddr=$(echo "$varThisHost" | awk -F ":" '{print $1}')
    varThisHostPort=$(echo "$varThisHost" | awk -F ":" '{print $2}')
    if [ "$varThisHostPort" = "443" ] || [ "$varThisHostPort" = "8443" ]; then
      echo "          <a href='https://$varThisHost' target='_blank'>$varThisHostAddr<br>Port $varThisHostPort</a>" >> "$varOutFile"
    else
      echo "          $varThisHostAddr<br>Port $varThisHostPort" >> "$varOutFile"
    fi
    echo "        </td>" >> "$varOutFile"

    # Table Cell: Server Checks
    echo "        <td>" >> "$varOutFile"
    # Check for session renegotiation for this host
    varTestGrep1=$(grep "$varThisHost" "$varSorted" | grep 'grep1SessionRenegotiation' | wc -l)
    if [ "$varTestGrep1" != "0" ]; then
      varGrep1=$(grep "$varThisHost" "$varSorted"| grep 'grep1SessionRenegotiation' | awk -F "," '{print "&#8226;" $3 "<br>"}')
      echo "          $varGrep1" >> "$varOutFile"
    fi
    # Check for compression for this host
    varTestGrep2=$(grep "$varThisHost" "$varSorted" | grep 'grep2Compression' | wc -l)
    if [ "$varTestGrep2" != "0" ]; then
      varGrep2=$(grep "$varThisHost" "$varSorted"| grep 'grep2Compression' | awk -F "," '{print "&#8226;" $3 "<br>"}')
      echo "          $varGrep2" >> "$varOutFile"
    fi
    # Check for heartbleed for this host
    varTestGrep3=$(grep "$varThisHost" "$varSorted" | grep 'grep3Heartbleed' | wc -l)
    if [ "$varTestGrep3" != "0" ]; then
      varGrep3=$(grep "$varThisHost" "$varSorted"| grep 'grep3Heartbleed' | awk -F "," '{print "          " "&#8226;" $3 "<br>"}')
      echo "          $varGrep3" >> "$varOutFile"
    fi
    echo "        </td>">> "$varOutFile"

    # Table Cell: Ciphers
    echo "        <td>" >> "$varOutFile"
    varTestGrep4=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | wc -l)
    if [ "$varTestGrep4" != "0" ]; then
      case "$varDoCiphers" in
        SUMMARY )
          varFlagSSLV2=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'SSLv2')
          if [ "$varFlagSSLV2" = "" ]; then
            echo "          &#8226;Any SSLv2: No<br>" >> "$varOutFile"
          else
            echo "          &#8226;Any SSLv2: Yes<br>" >> "$varOutFile"
          fi
          varFlagSSLV3=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'SSLv3')
          if [ "$varFlagSSLV3" = "" ]; then
            echo "          &#8226;Any SSLv3: No<br>" >> "$varOutFile"
          else
            echo "          &#8226;Any SSLv3: Yes<br>" >> "$varOutFile"
          fi
          varFlagTLSWeak=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'TLS' | grep -E ' 0 bits| 40 bits| 56 bits| 112 bits')
          if [ "$varFlagTLSWeak" = "" ]; then
            echo "          &#8226;TLS with &lt;128 Bit Ciphers: No<br>" >> "$varOutFile"
          else
            echo "          &#8226;TLS with &lt;128 Bit Ciphers: Yes<br>" >> "$varOutFile"
          fi
          varFlagTLSCrypto=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'TLS' | grep -E 'RC4|AECDH|ADH')
          if [ "$varFlagTLSCrypto" = "" ]; then
            echo "          &#8226;TLS with ADH, AECDH, or RC4: No<br>" >> "$varOutFile"
          else
            echo "          &#8226;TLS with ADH, AECDH, or RC4: Yes<br>" >> "$varOutFile"
          fi
          ;;
        WEAK | ALL )
          varGrep4=$(grep "$varThisHost" "$varSorted"| grep 'grep4Ciphers' | awk -F "," '{print "          " "&#8226;" $3 "<br>"}')
          echo "$varGrep4" >> "$varOutFile"
          ;;
      esac
    fi
    echo "        </td>" >> "$varOutFile"

    # Table Cell: Certificate
    echo "        <td>" >> "$varOutFile"
    # Check for subject for this host
    varTestGrep9=$(grep "$varThisHost" "$varSorted" | grep 'grep9Subject' | wc -l)
    if [ "$varTestGrep9" != "0" ]; then
      varGrep9=$(grep "$varThisHost" "$varSorted"| grep 'grep9Subject' | awk -F "," '{print $3 "<br>"}')
      echo "          &#8226;Subject: $varGrep9" >> "$varOutFile"
    fi
    # Check for issuer for this host
    varTestGrep5=$(grep "$varThisHost" "$varSorted" | grep 'grep5Issuer' | wc -l)
    if [ "$varTestGrep5" != "0" ]; then
      varGrep5=$(grep "$varThisHost" "$varSorted"| grep 'grep5Issuer' | awk -F "," '{print $3 "<br>"}')
      echo "          &#8226;Issuer: $varGrep5" >> "$varOutFile"
    fi
    # Check for signature algorithm for this host
    varTestGrep6=$(grep "$varThisHost" "$varSorted" | grep 'grep6SignatureAlgorithm' | wc -l)
    if [ "$varTestGrep6" != "0" ]; then
      varGrep6=$(grep "$varThisHost" "$varSorted"| grep 'grep6SignatureAlgorithm' | awk -F "," '{print $3 "<br>"}')
      echo "          &#8226;Signature Algorithm: $varGrep6" >> "$varOutFile"
    fi
    # Check for rsa key strength for this host
    varTestGrep7=$(grep "$varThisHost" "$varSorted" | grep 'grep7RSAKeyStrength' | wc -l)
    if [ "$varTestGrep7" != "0" ]; then
      varGrep7=$(grep "$varThisHost" "$varSorted"| grep 'grep7RSAKeyStrength' | awk -F "," '{print $3 "<br>"}')
      echo "          &#8226;RSA Key Strength: $varGrep7" >> "$varOutFile"
    fi
    # Check for expiration for this host
    varTestGrep8=$(grep "$varThisHost" "$varSorted" | grep 'grep8Expiration' | wc -l)
    if [ "$varTestGrep8" != "0" ]; then
      varGrep8=$(grep "$varThisHost" "$varSorted"| grep 'grep8Expiration' | awk -F "," '{print $3 "<br>"}')
      echo "          &#8226;Expiration: $varGrep8" >> "$varOutFile"
    fi
    echo "        </td>">> "$varOutFile"

    echo "      </tr>" >> "$varOutFile"

  done < "$varSortedHosts"

  # Write end of HTML file
  echo "    </table>" >> "$varOutFile"
  echo "  </body>" >> "$varOutFile"
  echo "</html>" >> "$varOutFile"  

  echo " Done."

}

varInFile="$1"
if [ ! -f "$varInFile" ]; then echo; echo "Error: Input file '$varInFile' does not exist."; fnUsage; fi
shift

while [ "$1" != "" ]; do
  case "$1" in
    -q )
      varQuiet="Y"
      ;;
    -r )
      shift
      varReportMode="$1"
      ;;
    -h )
      fnUsage
      ;;
    * )
      echo; echo "Error: Unrecognized parameter."; fnUsage
      ;;
  esac
  shift
done

case "$varReportMode" in
  1 )
    varReportType="STD"
    varDoCiphers="WEAK"
    varCipherText="Weak Ciphers"
    ;;
  2 )
    varReportType="STD"
    varDoCiphers="ALL"
    varCipherText="Accepted Ciphers"
    ;;
  3 )
    varReportType="FULL"
    varDoCiphers="SUMMARY"
    varCipherText="Weak Cipher Summary"
    ;;
  4 )
    varReportType="FULL"
    varDoCiphers="WEAK"
    varCipherText="Weak Ciphers"
    ;;
  5 )
    varReportType="FULL"
    varDoCiphers="ALL"
    varCipherText="Accepted Ciphers"
    ;;
  * )
    varReportMode="0"
    varReportType="STD"
    varDoCiphers="SUMMARY"
    varCipherText="Weak Cipher Summary"
    ;;
esac

echo
echo "=====================[ sslscanalyzer.sh - Ted R (github: actuated) ]====================="
echo
varCountServers=$(cat "$varInFile" | grep 'Testing SSL server' | wc -l)
echo "Converting $varInFile ($varCountServers SSL server/s) to $varOutFile."
echo
if [ "$varQuiet" = "N" ]; then read -p "Press Enter to confirm..."; echo; fi
mkdir "$varTemp"

fnProcessInFile
if [ "$varReportType" = "FULL" ]; then fnProcessResultsFull; fi
if [ "$varReportType" = "STD" ]; then fnProcessResultsStd; fi

if [ "$varQuiet" = "N" ] && [ -f "$varOutFile" ]; then echo; read -p "Open $varOutFile using sensible-browser? [Y/N] " varOpenOutput; echo; fi

case "$varOpenOutput" in
  y | Y)
    sensible-browser "$varOutFile" &
    ;;
esac

rm -r "$varTemp"
echo "=========================================[ fin ]========================================="
echo
