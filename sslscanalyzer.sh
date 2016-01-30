#!/bin/bash
# sslscanalyzer.sh
# 1/23/2015 by Ted R (http://github.com/actuated)
# Script to take an a file containing multiple sslscan results, and parse them for a summary table of findings
varDateCreated="1/23/2016"
varDateLastMod="1/29/2016"
# 1/25/2016 - Revised report options, replaced them with single -r option.
# 1/26/2016 - Added output option, and check for .htm/.html extension. Created CSS and font class tags to support color-coding for bad results in the future.
# 1/28/2016 - Added if to make sure host is set before checking lines in fnProcessInFile, also added continue commands to stop that loop run when a match is found.
# 1/29/2016 - Added colorize function, does not work for: compression, issuer, expiration (yet). Added --no-color option.
# 1/30/2016 - Added certificate expiration check and redirected sensible-browser stderror to /dev/null.

# NOTE - Weak ciphers currently identified with: grep -E 'SSLv2|SSLv3|TLSv1\.0.*.CBC| 0 bits| 40 bits| 56 bits| 112 bits|RC4|AECDH|ADH'

# Create temporary directory for processing
varYMDHMS=$(date +%F-%H-%M-%S)
varTemp="ssls-temp-$varYMDHMS"
if [ -e "$varTemp" ]; then rm -r "$varTemp"; fi
# Set name for HTML output file
varOutputTemp="$varTemp/output-temp.html"
varYMDHM=$(date +%F-%H-%M)
varOutFile="sslscanalyzer-$varYMDHM.html"
# Default values for options
varQuiet="N"
varReportMode="0"
varDoColor="Y"

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
  echo "[input file]   Your input file. Required. Must be the first parameter."
  echo
  echo "-r [value]     Report format options. See details below for supported values."
  echo
  echo "-o [filename]  Specify a custom output file. '.html' will be added if the filename does"
  echo "               not end in '.html/.htm'. Default is 'sslscanalyzer-YYYY-MM-DD-HH-MM.html'."
  echo
  echo "--no-color     Disable coloring 'bad' lines red."
  echo
  echo "-q             Optional 'quiet' switch. Disables pause for confirmation at the start of"
  echo "               the script, as well as the option to open the output file at the end."
  echo
  echo "-h             Displays this help/usage information."
  echo
  echo "===================================[ report settings ]==================================="
  echo
  echo "Standard: Fields are combined and categorized into 3 columns for each host, including:"
  echo "(1) SSL Server Checks - Session Renegotiation, Compression, and Heartbleed."
  echo "(2) Weak/accepted ciphers."
  echo "(3) Certificate - Subject, Issuer, Signature Algorithm, Key Space, and Expiration."
  echo
  echo "Full: Fields (as named above) are not combined. Each has its own column."
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
    if [ "$varHost" != "$varLastHost" ]; then echo "$varHost" >> "$varUnsortedHosts"; echo -n "."; continue; fi

    if [ "$varHost" != "" ]; then

      varCheckSessionRenegotiation=$(echo "$varLine" | grep -i 'session renegotiation')
      if [ "$varCheckSessionRenegotiation" != "" ]; then
        echo "$varHost,grep1SessionRenegotiation,$varCheckSessionRenegotiation" >> "$varParsed"
        continue
      fi

      varCheckCompression=$(echo "$varLine" | grep '^Compression ')
      if [ "$varCheckCompression" != "" ]; then
        echo "$varHost,grep2Compression,$varCheckCompression" >> "$varParsed"
        continue
      fi

      varCheckHeartbleed=$(echo "$varLine" | grep 'vulnerable to heartbleed')
      if [ "$varCheckHeartbleed" != "" ]; then
        echo "$varHost,grep3Heartbleed,$varCheckHeartbleed" >> "$varParsed"
        continue
      fi

      varCheckCiphers=$(echo "$varLine" | grep '^Accepted')
      if [ "$varCheckCiphers" != "" ]; then
        if [ "$varDoCiphers" = "ALL" ] || [ "$varDoCiphers" = "SUMMARY" ]; then
          varCiphers=$(echo "$varCheckCiphers" | awk '{print $2,"-",$3,$4,"-",$5}')
          echo "$varHost,grep4Ciphers,$varCiphers" >> "$varParsed"
          continue
        elif [ "$varDoCiphers" = "WEAK" ]; then
          varCiphers=$(echo "$varCheckCiphers" | grep -E 'SSLv2|SSLv3|TLSv1\.0.*.CBC| 0 bits| 40 bits| 56 bits| 112 bits|RC4|AECDH|ADH' | awk '{print $2,"-",$3,$4,"-",$5}')
          if [ "$varCiphers" != "" ]; then 
            echo "$varHost,grep4Ciphers,$varCiphers" >> "$varParsed"
            continue
          fi
        fi
      fi

      varCheckIssuers=$(echo "$varLine" | grep '^Issuer:' | grep -v '=')
      if [ "$varCheckIssuers" != "" ]; then
        varIssuer=$(echo "$varCheckIssuers" | awk '{$1=""; print $0}' | sed -e 's/^[ \t]*//')
        echo "$varHost,grep5Issuer,$varIssuer" >> "$varParsed"
        continue
      fi

      varCheckSignatureAlgorithm=$(echo "$varLine" | grep '^Signature Algorithm:')
      if [ "$varCheckSignatureAlgorithm" != "" ]; then
        varSignatureAlgorithm=$(echo "$varCheckSignatureAlgorithm" | awk '{print $3}')
        echo "$varHost,grep6SignatureAlgorithm,$varSignatureAlgorithm" >> "$varParsed"
        continue
      fi

      varCheckRSAKeyStrength=$(echo "$varLine" | grep '^RSA Key Strength:')
      if [ "$varCheckRSAKeyStrength" != "" ]; then
        varRSAKeyStrength=$(echo "$varCheckRSAKeyStrength" | awk '{print $4 " bits"}')
        echo "$varHost,grep7RSAKeyStrength,$varRSAKeyStrength" >> "$varParsed"
        continue
      fi

      varCheckExpiration=$(echo "$varLine" | grep 'Not valid after:')
      if [ "$varCheckExpiration" != "" ]; then
        varExpiration=$(echo "$varCheckExpiration" | awk '{print $4, $5, $6, $7}')
        echo "$varHost,grep8Expiration,$varExpiration" >> "$varParsed"
        continue
      fi

      varCheckSubject=$(echo "$varLine" | grep '^Subject:' | grep -v '=')
      if [ "$varCheckSubject" != "" ]; then
        varSubject=$(echo "$varCheckSubject" | awk '{print $2}')
        echo "$varHost,grep9Subject,$varSubject" >> "$varParsed"
        continue
      fi

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
  echo "<head>" >> "$varOutputTemp"
  echo "<title>sslscanalyzer.sh - Ted R (github: actuated)</title>" >> "$varOutputTemp"
  echo "<style>" >> "$varOutputTemp"
  echo "table, td {border: 2px solid black;" >> "$varOutputTemp"
  echo "border-collapse: collapse;}" >> "$varOutputTemp"
  echo "td {font-family: verdana, sans-serif;" >> "$varOutputTemp"
  echo "vertical-align: top;" >> "$varOutputTemp"
  echo "font-size: small;}" >> "$varOutputTemp"
  echo "td.heading {background-color: #3399FF;" >> "$varOutputTemp"
  echo "font-weight: bold;}" >> "$varOutputTemp"
  echo "a {color: #000000;}" >> "$varOutputTemp"
  echo ".ssls-normal {color: #000000;}" >> "$varOutputTemp"
  echo ".ssls-bad {color: #FF0000;}" >> "$varOutputTemp"
  echo "</style>" >> "$varOutputTemp"
  echo "</head>" >> "$varOutputTemp"
}

function fnProcessResultsFull {

  echo -n "Creating HTML report..."

  # Make sure varSorted/varSortedHosts files were created
  if [ ! -f "$varSorted" ]; then echo "Error: Couldn't parse any results from '$varInFile'."; echo; return; fi
  if [ ! -f "$varSortedHosts" ]; then echo "Error: Couldn't parse any results from '$varInFile'."; echo; return; fi

  # Write beginning of HTML file
  echo "<html>" > "$varOutputTemp"
  fnHTMLHead
  echo "<body>" >> "$varOutputTemp"
  echo "<table cellpadding='4'>" >> "$varOutputTemp"
  echo "<tr>" >> "$varOutputTemp"
  echo "<td colspan='10' class='heading'><font size='+1'><center>sslscanalyzer.sh - <a href='https://github.com/actuated' target='_blank'>Ted R (github: actuated)</a></center></font></td>" >> "$varOutputTemp"
  echo "</tr>" >> "$varOutputTemp"
  echo "<tr>" >> "$varOutputTemp"
  echo "<td rowspan='2' class='heading'>Host</td>" >> "$varOutputTemp"
  echo "<td colspan='4' class='heading'>SSL Server</td>" >> "$varOutputTemp"
  echo "<td colspan='5' class='heading'>Certificate</td>" >> "$varOutputTemp"
  echo "</tr>" >> "$varOutputTemp"
  echo "<tr>" >> "$varOutputTemp"
  echo "<td class='heading'>Session Renegotiation</td>" >> "$varOutputTemp"
  echo "<td class='heading'>Compression</td>" >> "$varOutputTemp"
  echo "<td class='heading'>Heartbleed</td>" >> "$varOutputTemp"
  echo "<td class='heading'>$varCipherText</td>" >> "$varOutputTemp"
  echo "<td class='heading'>Subject</td>" >> "$varOutputTemp"
  echo "<td class='heading'>Issuer</td>" >> "$varOutputTemp"
  echo "<td class='heading'>Signature Algorithm</td>" >> "$varOutputTemp"
  echo "<td class='heading'>Key Strength</td>" >> "$varOutputTemp"
  echo "<td class='heading'>Expiration</td>" >> "$varOutputTemp"
  echo "</tr>" >> "$varOutputTemp"

  # Process results for each host
  while read varThisHost; do

    echo -n "."

    echo "<tr>" >> "$varOutputTemp"

    # Table Cell: Host/Port
    echo "<td>" >> "$varOutputTemp"
    varThisHostAddr=$(echo "$varThisHost" | awk -F ":" '{print $1}')
    varThisHostPort=$(echo "$varThisHost" | awk -F ":" '{print $2}')
    if [ "$varThisHostPort" = "443" ] || [ "$varThisHostPort" = "8443" ]; then
      echo "<a href='https://$varThisHost' target='_blank'>$varThisHostAddr<br>Port $varThisHostPort</a>" >> "$varOutputTemp"
    else
      echo "$varThisHostAddr<br>Port $varThisHostPort" >> "$varOutputTemp"
    fi
    echo "</td>" >> "$varOutputTemp"

    # Check for session renegotion for this host
    varTestGrep1=$(grep "$varThisHost" "$varSorted" | grep 'grep1SessionRenegotiation' | wc -l)
    if [ "$varTestGrep1" = "0" ]; then
      echo "<td></td>" >> "$varOutputTemp"
    else
      varGrep1=$(grep "$varThisHost" "$varSorted"| grep 'grep1SessionRenegotiation' | awk -F "," '{print "<font class=ssls-normal>" $3 "</font><br>"}')
      echo "<td>$varGrep1</td>" >> "$varOutputTemp"
    fi

    # Check for compression for this host
    varTestGrep2=$(grep "$varThisHost" "$varSorted" | grep 'grep2Compression' | wc -l)
    if [ "$varTestGrep2" = "0" ]; then
      echo "<td></td>" >> "$varOutputTemp"
    else
      varGrep2=$(grep "$varThisHost" "$varSorted"| grep 'grep2Compression' | awk -F "," '{print "<font class=ssls-normal>" $3 "</font><br>"}')
      echo "<td>$varGrep2</td>" >> "$varOutputTemp"
    fi

    # Check for heartbleed for this host
    varTestGrep3=$(grep "$varThisHost" "$varSorted" | grep 'grep3Heartbleed' | wc -l)
    if [ "$varTestGrep3" = "0" ]; then
      echo "<td></td>" >> "$varOutputTemp"
    else
      varGrep3=$(grep "$varThisHost" "$varSorted"| grep 'grep3Heartbleed' | awk -F "," '{print "<font class=ssls-normal>&#8226;" $3 "</font><br>"}')
      echo "<td>" >> "$varOutputTemp"
      echo "$varGrep3" >> "$varOutputTemp"
      echo "</td>" >> "$varOutputTemp"
    fi

    # Table Cell: Ciphers
    echo "<td>" >> "$varOutputTemp"
    varTestGrep4=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | wc -l)
    if [ "$varTestGrep4" != "0" ]; then
      case "$varDoCiphers" in
        SUMMARY )
          varFlagSSLV2=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'SSLv2')
          if [ "$varFlagSSLV2" = "" ]; then
            echo "<font class=ssls-normal>&#8226;Any SSLv2: No</font><br>" >> "$varOutputTemp"
          else
            echo "<font class=ssls-normal>&#8226;Any SSLv2: Yes</font><br>" >> "$varOutputTemp"
          fi
          varFlagSSLV3=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'SSLv3')
          if [ "$varFlagSSLV3" = "" ]; then
            echo "<font class=ssls-normal>&#8226;Any SSLv3: No</font><br>" >> "$varOutputTemp"
          else
            echo "<font class=ssls-normal>&#8226;Any SSLv3: Yes</font><br>" >> "$varOutputTemp"
          fi
          varFlagTLS10CBC=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'TLSv1\.0' | grep -E 'CBC')
          if [ "$varFlagTLS10CBC" = "" ]; then
            echo "<font class=ssls-normal>&#8226;TLSv1.0 with CBC: No</font><br>" >> "$varOutputTemp"
          else
            echo "<font class=ssls-normal>&#8226;TLSv1.0 with CBC: Yes</font><br>" >> "$varOutputTemp"
          fi
          varFlagTLSWeak=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'TLS' | grep -E ' 0 bits| 40 bits| 56 bits| 112 bits')
          if [ "$varFlagTLSWeak" = "" ]; then
            echo "<font class=ssls-normal>&#8226;TLSv1.x with &lt;128 Bit Ciphers: No</font><br>" >> "$varOutputTemp"
          else
            echo "<font class=ssls-normal>&#8226;TLSv1.x with &lt;128 Bit Ciphers: Yes</font><br>" >> "$varOutputTemp"
          fi
          varFlagTLSCrypto=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'TLS' | grep -E 'RC4|AECDH|ADH')
          if [ "$varFlagTLSCrypto" = "" ]; then
            echo "<font class=ssls-normal>&#8226;TLSv1.x with ADH, AECDH, or RC4: No</font><br>" >> "$varOutputTemp"
          else
            echo "<font class=ssls-normal>&#8226;TLSv1.x with ADH, AECDH, or RC4: Yes</font><br>" >> "$varOutputTemp"
          fi
          ;;
        WEAK | ALL )
          varGrep4=$(grep "$varThisHost" "$varSorted"| grep 'grep4Ciphers' | awk -F "," '{print "<font class=ssls-normal>&#8226;" $3 "</font><br>"}')
          echo "$varGrep4" >> "$varOutputTemp"
          ;;
      esac
    fi
    echo "</td>" >> "$varOutputTemp"

    # Check for subject for this host
    varTestGrep9=$(grep "$varThisHost" "$varSorted" | grep 'grep9Subject' | wc -l)
    if [ "$varTestGrep9" = "0" ]; then
      echo "<td></td>" >> "$varOutputTemp"
    else
      varGrep9=$(grep "$varThisHost" "$varSorted"| grep 'grep9Subject' | awk -F "," '{print "<font class=ssls-normal>" $3 "</font><br>"}')
      echo "<td>$varGrep9</td>" >> "$varOutputTemp"
    fi

    # Check for issuer for this host
    varTestGrep5=$(grep "$varThisHost" "$varSorted" | grep 'grep5Issuer' | wc -l)
    if [ "$varTestGrep5" = "0" ]; then
      echo "<td></td>" >> "$varOutputTemp"
    else
      varGrep5=$(grep "$varThisHost" "$varSorted"| grep 'grep5Issuer' | awk -F "," '{print "<font class=ssls-normal>" $3 "</font><br>"}')
      echo "<td>$varGrep5</td>" >> "$varOutputTemp"
    fi

    # Check for signature algorithm for this host
    varTestGrep6=$(grep "$varThisHost" "$varSorted" | grep 'grep6SignatureAlgorithm' | wc -l)
    if [ "$varTestGrep6" = "0" ]; then
      echo "<td></td>" >> "$varOutputTemp"
    else
      varGrep6=$(grep "$varThisHost" "$varSorted"| grep 'grep6SignatureAlgorithm' | awk -F "," '{print "<font class=ssls-normal>" $3 "</font><br>"}')
      echo "<td>$varGrep6</td>" >> "$varOutputTemp"
    fi

    # Check for rsa key strength for this host
    varTestGrep7=$(grep "$varThisHost" "$varSorted" | grep 'grep7RSAKeyStrength' | wc -l)
    if [ "$varTestGrep7" = "0" ]; then
      echo "<td></td>" >> "$varOutputTemp"
    else
      varGrep7=$(grep "$varThisHost" "$varSorted"| grep 'grep7RSAKeyStrength' | awk -F "," '{print "<font class=ssls-normal>" $3 "</font><br>"}')
      echo "<td>$varGrep7</td>" >> "$varOutputTemp"
    fi

    # Check for expiration for this host
    varTestGrep8=$(grep "$varThisHost" "$varSorted" | grep 'grep8Expiration' | wc -l)
    if [ "$varTestGrep8" = "0" ]; then
      echo "<td></td>" >> "$varOutputTemp"
    else
      varGrep8=$(grep "$varThisHost" "$varSorted"| grep 'grep8Expiration' | awk -F "," '{print "<font class=ssls-normal>" $3 "</font><br>"}')
      echo "<td>$varGrep8</td>" >> "$varOutputTemp"
    fi

    echo "</tr>" >> "$varOutputTemp"
  
  done < "$varSortedHosts"

  # Write end of HTML file
  echo "</table>" >> "$varOutputTemp"
  echo "</body>" >> "$varOutputTemp"
  echo "</html>" >> "$varOutputTemp"  

  echo " Done."

}

function fnProcessResultsStd {

  echo -n "Creating HTML report..."

  # Make sure varSorted/varSortedHosts files were created
  if [ ! -f "$varSorted" ]; then echo "Error: Couldn't parse any results from '$varInFile'."; echo; return; fi
  if [ ! -f "$varSortedHosts" ]; then echo "Error: Couldn't parse any results from '$varInFile'."; echo; return; fi

  # Write beginning of HTML file
  echo "<html>" > "$varOutputTemp"
  fnHTMLHead
  echo "<body>" >> "$varOutputTemp"
  echo "<table cellpadding='4'>" >> "$varOutputTemp"
  echo "<tr>" >> "$varOutputTemp"
  echo "<td colspan='4' class='heading'><font size='+1'><center>sslscanalyzer.sh - <a href='https://github.com/actuated' target='_blank'>Ted R (github: actuated)</a></center></font></td>" >> "$varOutputTemp"
  echo "</tr>" >> "$varOutputTemp"
  echo "<tr>" >> "$varOutputTemp"
  echo "<td class='heading'>Host</td>" >> "$varOutputTemp"
  echo "<td class='heading'>SSL Server Checks</td>" >> "$varOutputTemp"
  echo "<td class='heading'>SSL Server: $varCipherText</td>" >> "$varOutputTemp"
  echo "<td class='heading'>Certificate</td>" >> "$varOutputTemp"
  echo "</tr>" >> "$varOutputTemp"

  # Process results for each host
  while read varThisHost; do

    echo -n "."

    echo "<tr>" >> "$varOutputTemp"

    # Table Cell: Host/Port
    echo "<td>" >> "$varOutputTemp"
    varThisHostAddr=$(echo "$varThisHost" | awk -F ":" '{print $1}')
    varThisHostPort=$(echo "$varThisHost" | awk -F ":" '{print $2}')
    if [ "$varThisHostPort" = "443" ] || [ "$varThisHostPort" = "8443" ]; then
      echo "<a href='https://$varThisHost' target='_blank'>$varThisHostAddr<br>Port $varThisHostPort</a>" >> "$varOutputTemp"
    else
      echo "$varThisHostAddr<br>Port $varThisHostPort" >> "$varOutputTemp"
    fi
    echo "</td>" >> "$varOutputTemp"

    # Table Cell: Server Checks
    echo "<td>" >> "$varOutputTemp"
    # Check for session renegotiation for this host
    varTestGrep1=$(grep "$varThisHost" "$varSorted" | grep 'grep1SessionRenegotiation' | wc -l)
    if [ "$varTestGrep1" != "0" ]; then
      varGrep1=$(grep "$varThisHost" "$varSorted"| grep 'grep1SessionRenegotiation' | awk -F "," '{print "<font class=ssls-normal>&#8226;" $3 "</font><br>"}')
      echo "$varGrep1" >> "$varOutputTemp"
    fi
    # Check for compression for this host
    varTestGrep2=$(grep "$varThisHost" "$varSorted" | grep 'grep2Compression' | wc -l)
    if [ "$varTestGrep2" != "0" ]; then
      varGrep2=$(grep "$varThisHost" "$varSorted"| grep 'grep2Compression' | awk -F "," '{print "<font class=ssls-normal>&#8226;" $3 "</font><br>"}')
      echo "$varGrep2" >> "$varOutputTemp"
    fi
    # Check for heartbleed for this host
    varTestGrep3=$(grep "$varThisHost" "$varSorted" | grep 'grep3Heartbleed' | wc -l)
    if [ "$varTestGrep3" != "0" ]; then
      varGrep3=$(grep "$varThisHost" "$varSorted"| grep 'grep3Heartbleed' | awk -F "," '{print "<font class=ssls-normal>&#8226;" $3 "</font><br>"}')
      echo "$varGrep3" >> "$varOutputTemp"
    fi
    echo "</td>">> "$varOutputTemp"

    # Table Cell: Ciphers
    echo "<td>" >> "$varOutputTemp"
    varTestGrep4=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | wc -l)
    if [ "$varTestGrep4" != "0" ]; then
      case "$varDoCiphers" in
        SUMMARY )
          varFlagSSLV2=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'SSLv2')
          if [ "$varFlagSSLV2" = "" ]; then
            echo "<font class=ssls-normal>&#8226;Any SSLv2: No</font><br>" >> "$varOutputTemp"
          else
            echo "<font class=ssls-normal>&#8226;Any SSLv2: Yes</font><br>" >> "$varOutputTemp"
          fi
          varFlagSSLV3=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'SSLv3')
          if [ "$varFlagSSLV3" = "" ]; then
            echo "<font class=ssls-normal>&#8226;Any SSLv3: No</font><br>" >> "$varOutputTemp"
          else
            echo "<font class=ssls-normal>&#8226;Any SSLv3: Yes</font><br>" >> "$varOutputTemp"
          fi
          varFlagTLS10CBC=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'TLSv1\.0' | grep -E 'CBC')
          if [ "$varFlagTLS10CBC" = "" ]; then
            echo "<font class=ssls-normal>&#8226;TLSv1.0 with CBC: No</font><br>" >> "$varOutputTemp"
          else
            echo "<font class=ssls-normal>&#8226;TLSv1.0 with CBC: Yes</font><br>" >> "$varOutputTemp"
          fi
          varFlagTLSWeak=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'TLS' | grep -E ' 0 bits| 40 bits| 56 bits| 112 bits')
          if [ "$varFlagTLSWeak" = "" ]; then
            echo "<font class=ssls-normal>&#8226;TLSv1.x with &lt;128 Bit Ciphers: No</font><br>" >> "$varOutputTemp"
          else
            echo "<font class=ssls-normal>&#8226;TLSv1.x with &lt;128 Bit Ciphers: Yes</font><br>" >> "$varOutputTemp"
          fi
          varFlagTLSCrypto=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'TLS' | grep -E 'RC4|AECDH|ADH')
          if [ "$varFlagTLSCrypto" = "" ]; then
            echo "<font class=ssls-normal>&#8226;TLSv1.x with ADH, AECDH, or RC4: No</font><br>" >> "$varOutputTemp"
          else
            echo "<font class=ssls-normal>&#8226;TLSv1.x with ADH, AECDH, or RC4: Yes</font><br>" >> "$varOutputTemp"
          fi
          ;;
        WEAK | ALL )
          varGrep4=$(grep "$varThisHost" "$varSorted"| grep 'grep4Ciphers' | awk -F "," '{print "<font class=ssls-normal>&#8226;" $3 "</font><br>"}')
          echo "$varGrep4" >> "$varOutputTemp"
          ;;
      esac
    fi
    echo "</td>" >> "$varOutputTemp"

    # Table Cell: Certificate
    echo "<td>" >> "$varOutputTemp"
    # Check for subject for this host
    varTestGrep9=$(grep "$varThisHost" "$varSorted" | grep 'grep9Subject' | wc -l)
    if [ "$varTestGrep9" != "0" ]; then
      varGrep9=$(grep "$varThisHost" "$varSorted"| grep 'grep9Subject' | awk -F "," '{print $3 "<br>"}')
      echo "<font class=ssls-normal>&#8226;Subject: $varGrep9</font>" >> "$varOutputTemp"
    fi
    # Check for issuer for this host
    varTestGrep5=$(grep "$varThisHost" "$varSorted" | grep 'grep5Issuer' | wc -l)
    if [ "$varTestGrep5" != "0" ]; then
      varGrep5=$(grep "$varThisHost" "$varSorted"| grep 'grep5Issuer' | awk -F "," '{print $3 "<br>"}')
      echo "<font class=ssls-normal>&#8226;Issuer: $varGrep5</font>" >> "$varOutputTemp"
    fi
    # Check for signature algorithm for this host
    varTestGrep6=$(grep "$varThisHost" "$varSorted" | grep 'grep6SignatureAlgorithm' | wc -l)
    if [ "$varTestGrep6" != "0" ]; then
      varGrep6=$(grep "$varThisHost" "$varSorted"| grep 'grep6SignatureAlgorithm' | awk -F "," '{print $3 "<br>"}')
      echo "<font class=ssls-normal>&#8226;Signature Algorithm: $varGrep6</font>" >> "$varOutputTemp"
    fi
    # Check for rsa key strength for this host
    varTestGrep7=$(grep "$varThisHost" "$varSorted" | grep 'grep7RSAKeyStrength' | wc -l)
    if [ "$varTestGrep7" != "0" ]; then
      varGrep7=$(grep "$varThisHost" "$varSorted"| grep 'grep7RSAKeyStrength' | awk -F "," '{print $3 "<br>"}')
      echo "<font class=ssls-normal>&#8226;RSA Key Strength: $varGrep7</font>" >> "$varOutputTemp"
    fi
    # Check for expiration for this host
    varTestGrep8=$(grep "$varThisHost" "$varSorted" | grep 'grep8Expiration' | wc -l)
    if [ "$varTestGrep8" != "0" ]; then
      varGrep8=$(grep "$varThisHost" "$varSorted"| grep 'grep8Expiration' | awk -F "," '{print $3 "<br>"}')
      echo "<font class=ssls-normal>&#8226;Expiration: $varGrep8</font>" >> "$varOutputTemp"
    fi
    echo "</td>">> "$varOutputTemp"

    echo "</tr>" >> "$varOutputTemp"

  done < "$varSortedHosts"

  # Write end of HTML file
  echo "</table>" >> "$varOutputTemp"
  echo "</body>" >> "$varOutputTemp"
  echo "</html>" >> "$varOutputTemp"  

  echo " Done."

}

function fnColorize {

  if [ -f "$varOutFile" ]; then rm "$varOutFile"; fi

  if [ "$varDoColor" = "Y" ]; then

    echo -n "Colorizing 'bad' results... "
 
    while read -r varLineInput; do

      varMarkThisBad="N"

      varOutCheckSessionReneg=$(echo "$varLineInput" | grep 'Insecure session renegotiation supported')
      if [ "$varOutCheckSessionReneg" != "" ]; then varMarkThisBad="Y"; fi

      # COMPRESSION

      varOutCheckHeartbleed=$(echo "$varLineInput" | grep 'TLS 1\.. vulnerable to heartbleed')
      if [ "$varOutCheckHeartbleed" != "" ]; then varMarkThisBad="Y"; fi

      varOutCheckSHA1Cert=$(echo "$varLineInput" | grep 'sha1WithRSAEncryption')
      if [ "$varOutCheckSHA1Cert" != "" ]; then varMarkThisBad="Y"; fi

      varOutCheckMD5Cert=$(echo "$varLineInput" | grep 'md5WithRSAEncryption')
      if [ "$varOutCheckMD5Cert" != "" ]; then varMarkThisBad="Y"; fi

      varOutCheck1024BitCert=$(echo "$varLineInput" | grep '1024 bits<br><.font>$')
      if [ "$varOutCheck1024BitCert" != "" ]; then varMarkThisBad="Y"; fi

      if [ "$varDoCiphers" = "SUMMARY" ]; then
        varOutCheckSSLv2_Summary=$(echo "$varLineInput" | grep 'Any SSLv2: Yes')
        if [ "$varOutCheckSSLv2_Summary" != "" ]; then varMarkThisBad="Y"; fi
        varOutCheckSSLv3_Summary=$(echo "$varLineInput" | grep 'Any SSLv3: Yes')
        if [ "$varOutCheckSSLv3_Summary" != "" ]; then varMarkThisBad="Y"; fi
        varOutCheckTLSCBC_Summary=$(echo "$varLineInput" | grep 'TLSv1\.0 with CBC: Yes')
        if [ "$varOutCheckTLSCBC_Summary" != "" ]; then varMarkThisBad="Y"; fi
        varOutCheckTLS128_Summary=$(echo "$varLineInput" | grep 'TLSv1\.x with .*.128 Bit Ciphers: Yes')
        if [ "$varOutCheckTLS128_Summary" != "" ]; then varMarkThisBad="Y"; fi
        varOutCheckTLSEnc_Summary=$(echo "$varLineInput" | grep 'TLSv1.x with ADH, AECDH, or RC4: Yes')
        if [ "$varOutCheckTLSEnc_Summary" != "" ]; then varMarkThisBad="Y"; fi
      else
        varOutCheckWeakCiphers=$(echo "$varLineInput" | grep ' - ' | grep -E 'SSLv2|SSLv3|TLSv1\.0.*.CBC| 0 bits| 40 bits| 56 bits| 112 bits|RC4|AECDH|ADH')
        if [ "$varOutCheckWeakCiphers" != "" ]; then varMarkThisBad="Y"; fi      
      fi

      varOutCheckCertExp=$(echo "$varLineInput" | grep -o '[[:alpha:]]*.[[:digit:]]*.[[:digit:]]*:[[:digit:]]*:[[:digit:]]*.[[:digit:]]*')
      if [ "$varOutCheckCertExp" != "" ]; then
        varCertExpPreCheckMonth=$(echo "$varOutCheckCertExp" | awk '{print $1}')
        case "$varCertExpPreCheckMonth" in
          Jan )
            varOutCheckMonth="01"
            ;;
          Feb )
            varOutCheckMonth="02"
            ;;
          Mar )
            varOutCheckMonth="03"
            ;;
          Apr )
            varOutCheckMonth="04"
            ;;
          May )
            varOutCheckMonth="05"
            ;;
          Jun )
            varOutCheckMonth="06"
            ;;
          Jul )
            varOutCheckMonth="07"
            ;;
          Aug )
            varOutCheckMonth="08"
            ;;
          Sep )
            varOutCheckMonth="09"
            ;;
          Oct )
            varOutCheckMonth="10"
            ;;
          Nov )
            varOutCheckMonth="11"
            ;;
          Dec )
            varOutCheckMonth="12"
            ;;
        esac
        varCertExpPreCheckDay=$(echo "$varOutCheckCertExp" | awk '{print $2}')
        let varCertExpPreCheckDay=varCertExpPreCheckDay+1
        if [ "$varCertExpPreCheckDay" -le "9" ]; then
          varOutCheckDay="0$varCertExpPreCheckDay"
        else
          varOutCheckDay="$varCertExpPreCheckDay"
        fi
        varOutCheckYear=$(echo "$varOutCheckCertExp" | awk '{print $4}')
        varOutCheckYYYYMMDD="$varOutCheckYear$varOutCheckMonth$varOutCheckDay"
        varOutCheckToday=$(date +%Y%m%d)
        if [ "$varOutCheckYYYYMMDD" -le "$varOutCheckToday" ]; then varMarkThisBad="Y"; fi
      fi

      if [ "$varMarkThisBad" = "Y" ]; then
        echo "$varLineInput" | sed 's/ssls-normal/ssls-bad/g' >> "$varOutFile"
      else
        echo "$varLineInput" >> "$varOutFile"
      fi

    done < "$varOutputTemp"
    echo "Done."
  else
    mv "$varOuputTemp" "$varOutFile"
  fi

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
    -o )
      shift
      varOutFileInput="$1"
      ;;
    --no-color )
      varDoColor="N"
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

if [ "$varOutFileInput" != "" ]; then
  varOFIHTM=$(echo "$varOutFileInput" | grep -i '\.htm$')
  varOFIHTML=$(echo "$varOutFileInput" | grep -i '\.html$')
  if [ "$varOFIHTM" = "" ] && [ "$varOFIHTML" = "" ]; then
    varOutFileInput="$varOutFileInput.html"
  fi
  varOutFile="$varOutFileInput"
fi

echo
echo "=====================[ sslscanalyzer.sh - Ted R (github: actuated) ]====================="
echo
varCountServers=$(cat "$varInFile" | grep 'Testing SSL server' | wc -l)
echo "Converting $varInFile ($varCountServers SSL server/s) to $varOutFile."
echo
if [ -f "$varOutFile" ]; then echo "Warning: Continuing will overwrite $varOutFile."; echo; fi
if [ "$varQuiet" = "N" ]; then read -p "Press Enter to confirm..."; echo; fi
mkdir "$varTemp"

fnProcessInFile
if [ "$varReportType" = "FULL" ]; then fnProcessResultsFull; fi
if [ "$varReportType" = "STD" ]; then fnProcessResultsStd; fi
fnColorize

if [ "$varQuiet" = "N" ] && [ -f "$varOutFile" ]; then echo; read -p "Open $varOutFile using sensible-browser? [Y/N] " varOpenOutput; fi

case "$varOpenOutput" in
  y | Y)
    sensible-browser "$varOutFile" 2> /dev/null &
    ;;
esac

rm -r "$varTemp"
echo
echo "=========================================[ fin ]========================================="
echo
