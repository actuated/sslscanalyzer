#!/bin/bash
# sslscanalyzer.sh (v2.0)
# v1.0 - 1/23/2016 by Ted R (http://github.com/actuated)
# v2.0 - 12/20/2016
# Script to take an a file containing multiple sslscan results, and parse them for an HTML table of findings
# 3/5/2017 - Added --no-links option, set font family to Arial and font size to 15px (11pt).
varDateCreated="1/23/2016"
varDateLastMod="3/5/2017"

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
varSkipColorFn="N"
varDoSslScan="N"
# Minimum width for minimal/inverted reports
varMinTblWidth="750"
varDoLinks="Y"

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
  echo "[input file]        Your input file. Required. Must be the first parameter."
  echo
  echo "-o [filename]       Specify a custom output file. '.html' will be added if the filename"
  echo "                    does not end in '.html/.htm'. Default is"
  echo "                    'sslscanalyzer-YYYY-MM-DD-HH-MM.html'."
  echo
  echo "-q                  Optional 'quiet' switch. Disables pause for confirmation at the start"
  echo "                    of the script, as well as the option to open the output file at the"
  echo "                    end."
  echo
  echo "-r [value]          Report format options. See details below for supported values."
  echo
  echo "--no-color          Disable coloring 'bad' lines red."
  echo
  echo "--do-sslscan        Start by running 'sslscan --show-certificate'. Uses [input file] as"
  echo "                    the list of targets instead of a list of results."
  echo
  echo "--no-links          Don't create links for HTTPS hosts."
  echo
  echo "-h                  Displays this help/usage information."
  echo
  echo "===================================[ report settings ]==================================="
  echo
  echo "Values for -r:"
  echo
  echo " 0  Default. Minimal table listing accepted ciphers by host."
  echo " 1  Minimal table listing Yes/No summary by host."
  echo " 2  Inverted listing of hosts per result."
  echo " 3  Summary report listing server checks, accepted ciphers, and cert info by host."
  echo " 4  Summary report listing server checks, Yes/No summary, and cert info by host."
  echo " 5  Full report with all accepted ciphers listed."
  echo " 6  Full report with Yes/No summary for ciphers."
  echo
  exit
}

function fnDoCipherCell {
      case "$varDoCiphers" in
        boolean )
        varFlagSSLV2=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'SSLv2')
        if [ "$varFlagSSLV2" = "" ]; then
          echo "<font class=ssls-normal>&#8226;Any SSLv2: No</font><br>" >> "$varOutputTemp"
        else
          echo "<font class=ssls-red>&#8226;Any SSLv2: Yes</font><br>" >> "$varOutputTemp"
        fi
        varFlagSSLV3=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'SSLv3')
        if [ "$varFlagSSLV3" = "" ]; then
          echo "<font class=ssls-normal>&#8226;Any SSLv3: No</font><br>" >> "$varOutputTemp"
        else
          echo "<font class=ssls-red>&#8226;Any SSLv3: Yes</font><br>" >> "$varOutputTemp"
        fi
        varFlagTLS10=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'TLSv1\.0')
        if [ "$varFlagTLS10" = "" ]; then
          echo "<font class=ssls-normal>&#8226;Any TLSv1.0: No</font><br>" >> "$varOutputTemp"
        else
          echo "<font class=ssls-red>&#8226;Any TLSv1.0: Yes</font><br>" >> "$varOutputTemp"
        fi
        varFlagTLS11=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'TLSv1\.1')
        if [ "$varFlagTLS11" = "" ]; then
          echo "<font class=ssls-normal>&#8226;Any TLSv1.1: No</font><br>" >> "$varOutputTemp"
        else
          echo "<font class=ssls-orange>&#8226;Any TLSv1.1: Yes</font><br>" >> "$varOutputTemp"
        fi
        varFlagTLS11Weak=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'TLSv1\.1' | grep -E ' 0 bits| 40 bits| 56 bits| 112 bits')
        if [ "$varFlagTLS11Weak" = "" ]; then
          echo "<font class=ssls-normal>&#8226;TLSv1.1 with &lt;128 Bit Ciphers: No</font><br>" >> "$varOutputTemp"
        else
          echo "<font class=ssls-red>&#8226;TLSv1.1 with &lt;128 Bit Ciphers: Yes</font><br>" >> "$varOutputTemp"
        fi
        varFlagTLS11Crypto=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'TLSv1\.1' | grep -E 'RC4|AECDH|ADH')
        if [ "$varFlagTLS11Crypto" = "" ]; then
          echo "<font class=ssls-normal>&#8226;TLSv1.1 with ADH, AECDH, or RC4: No</font><br>" >> "$varOutputTemp"
        else
          echo "<font class=ssls-red>&#8226;TLSv1.1 with ADH, AECDH, or RC4: Yes</font><br>" >> "$varOutputTemp"
        fi
        varFlagTLS12Weak=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'TLSv1\.2' | grep -E ' 0 bits| 40 bits| 56 bits| 112 bits')
        if [ "$varFlagTLSWeak" = "" ]; then
          echo "<font class=ssls-normal>&#8226;TLSv1.2 with &lt;128 Bit Ciphers: No</font><br>" >> "$varOutputTemp"
        else
          echo "<font class=ssls-red>&#8226;TLSv1.2 with &lt;128 Bit Ciphers: Yes</font><br>" >> "$varOutputTemp"
        fi
        varFlagTLS12Crypto=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | grep 'TLSv1\.2' | grep -E 'RC4|AECDH|ADH')
        if [ "$varFlagTLS12Crypto" = "" ]; then
          echo "<font class=ssls-normal>&#8226;TLSv1.2 with ADH, AECDH, or RC4: No</font><br>" >> "$varOutputTemp"
        else
          echo "<font class=ssls-red>&#8226;TLSv1.2 with ADH, AECDH, or RC4: Yes</font><br>" >> "$varOutputTemp"
        fi
        ;;
      accepted )
        varGrep4=$(grep "$varThisHost" "$varSorted"| grep 'grep4Ciphers' | awk -F "," '{print "<font class=ssls-normal>&#8226;" $3 "</font><br>"}')
        echo "$varGrep4" >> "$varOutputTemp"
        ;;
    esac
}

function fnHTMLHead {
  echo "<html>" >> "$varOutputTemp"
  echo "<head>" >> "$varOutputTemp"
  echo "<title>sslscanalyzer.sh - Ted R (github: actuated)</title>" >> "$varOutputTemp"
  echo "<style>" >> "$varOutputTemp"
  echo "table, td {border: 2px solid black;" >> "$varOutputTemp"
  echo "border-collapse: collapse;}" >> "$varOutputTemp"
  echo "td {font-family: arial, sans-serif;" >> "$varOutputTemp"
  echo "vertical-align: top;" >> "$varOutputTemp"
  echo "font-size: 15px;}" >> "$varOutputTemp"
  echo "a {color: #000000;}" >> "$varOutputTemp"
  echo ".ssls-normal {color: #000000;}" >> "$varOutputTemp"
  if [ "$varDoColor" = "Y" ]; then
    echo ".ssls-red {color: #FF0000;}" >> "$varOutputTemp"
    echo ".ssls-orange {color: #FF8033;}" >> "$varOutputTemp"
    echo "td.heading {background-color: #3399FF;" >> "$varOutputTemp"
    echo "font-weight: bold;}" >> "$varOutputTemp"
  else
    echo ".ssls-red {color: #000000;}" >> "$varOutputTemp"
    echo ".ssls-orange {color: #000000;}" >> "$varOutputTemp"
    echo "td.heading {background-color: #777777;" >> "$varOutputTemp"
    echo "font-weight: bold;}" >> "$varOutputTemp"
  fi
  echo "</style>" >> "$varOutputTemp"
  echo "</head>" >> "$varOutputTemp"
}

function fnCreateMinimalReport {

  echo -n "Creating HTML report..."

  # Make sure varSorted/varSortedHosts files were created
  if [ ! -f "$varSorted" ]; then echo "Error: Couldn't parse any results from '$varInFile'."; echo; return; fi
  if [ ! -f "$varSortedHosts" ]; then echo "Error: Couldn't parse any results from '$varInFile'."; echo; return; fi

  # Write beginning of HTML file
  fnHTMLHead
  echo "<body>" >> "$varOutputTemp"
  echo "<table cellpadding='4' width='$varMinTblWidth'>" >> "$varOutputTemp"
  echo "<tr>" >> "$varOutputTemp"
  echo "<td colspan='2' class='heading'><font size='+1'><center>sslscanalyzer.sh - <a href='https://github.com/actuated' target='_blank'>Ted R (github: actuated)</a></center></font></td>" >> "$varOutputTemp"
  echo "</tr>" >> "$varOutputTemp"
  echo "<tr>" >> "$varOutputTemp"
  echo "<td class='heading'>Host</td>" >> "$varOutputTemp"
  echo "<td class='heading'>$varCipherText</td>" >> "$varOutputTemp"
  echo "</tr>" >> "$varOutputTemp"

  # Process results for each host
  while read varThisHost; do

    echo -n "."

    echo "<tr>" >> "$varOutputTemp"

    # Table Cell: Host/Port
    echo "<td>" >> "$varOutputTemp"
    varThisHostAddr=$(echo "$varThisHost" | awk -F ":" '{print $1}')
    varThisHostPort=$(echo "$varThisHost" | awk -F ":" '{print $2}')
    if [ "$varThisHostPort" = "443" ] || [ "$varThisHostPort" = "8443" ] && [ "$varDoLinks" = "Y" ]; then
      echo "<a href='https://$varThisHost' target='_blank'>$varThisHostAddr<br>Port $varThisHostPort</a>" >> "$varOutputTemp"
    else
      echo "$varThisHostAddr<br>Port $varThisHostPort" >> "$varOutputTemp"
    fi
    echo "</td>" >> "$varOutputTemp"

    # Table Cell: Ciphers
    echo "<td>" >> "$varOutputTemp"
    varTestGrep4=$(grep "$varThisHost" "$varSorted" | grep 'grep4Ciphers' | wc -l)
    if [ "$varTestGrep4" != "0" ]; then
      fnDoCipherCell
    fi
    echo "</td>" >> "$varOutputTemp"

    echo "</tr>" >> "$varOutputTemp"

  done < "$varSortedHosts"

  # Write end of HTML file
  echo "</table>" >> "$varOutputTemp"
  echo "</body>" >> "$varOutputTemp"
  echo "</html>" >> "$varOutputTemp"  

  echo " Done."

}

function fnCreateInvertedReport {

  echo -n "Creating HTML report..."

  # Make sure varSorted/varSortedHosts files were created
  if [ ! -f "$varSorted" ]; then echo "Error: Couldn't parse any results from '$varInFile'."; echo; return; fi
  if [ ! -f "$varSortedHosts" ]; then echo "Error: Couldn't parse any results from '$varInFile'."; echo; return; fi

  # Write beginning of HTML file
  fnHTMLHead
  echo "<body>" >> "$varOutputTemp"
  echo "<table cellpadding='4' width='$varMinTblWidth'>" >> "$varOutputTemp"
  echo "<tr>" >> "$varOutputTemp"
  echo "<td colspan='2' class='heading'><font size='+1'><center>sslscanalyzer.sh - <a href='https://github.com/actuated' target='_blank'>Ted R (github: actuated)</a></center></font></td>" >> "$varOutputTemp"
  echo "</tr>" >> "$varOutputTemp"
  echo "<tr>" >> "$varOutputTemp"
  echo "<td class='heading'>Server Connections Accepted</td>" >> "$varOutputTemp"
  echo "<td class='heading'>Affected Hosts/Services</td>" >> "$varOutputTemp"
  echo "</tr>" >> "$varOutputTemp"

  # Process results for each condition
  # SSLv2
  echo "<tr>" >> "$varOutputTemp"
  echo "<td>SSLv2 Accepted:</td>" >> "$varOutputTemp"
  varInvSsl2=$(grep 'SSLv2' "$varSorted" | awk -F "," '{print $1 "<br>"}' | sort -V -u)
  if [ "$varInvSsl2" = "" ]; then
    echo "<td>None</td>" >> "$varOutputTemp"
  else
    echo "<td><font class='ssls-red'>$varInvSsl2</font></td>" >> "$varOutputTemp"
  fi
  echo "</tr>" >> "$varOutputTemp"
  # SSLv3
  echo "<tr>" >> "$varOutputTemp"
  echo "<td>SSLv3 Accepted:</td>" >> "$varOutputTemp"
  varInvSsl3=$(grep 'SSLv3' "$varSorted" | awk -F "," '{print $1 "<br>"}' | sort -V -u)
  if [ "$varInvSsl3" = "" ]; then
    echo "<td>None</td>" >> "$varOutputTemp"
  else
    echo "<td><font class='ssls-red'>$varInvSsl3</font></td>" >> "$varOutputTemp"
  fi
  echo "</tr>" >> "$varOutputTemp"
  # TLSv1.0
  echo "<tr>" >> "$varOutputTemp"
  echo "<td>TLSv1.0 Accepted:</td>" >> "$varOutputTemp"
  varInvTls10=$(grep 'TLSv1\.0' "$varSorted" | awk -F "," '{print $1 "<br>"}' | sort -V -u)
  if [ "$varInvTls10" = "" ]; then
    echo "<td>None</td>" >> "$varOutputTemp"
  else
    echo "<td><font class='ssls-red'>$varInvTls10</font></td>" >> "$varOutputTemp"
  fi
  echo "</tr>" >> "$varOutputTemp"
  # TLSv1.1
  echo "<tr>" >> "$varOutputTemp"
  echo "<td>TLSv1.1 Accepted:</td>" >> "$varOutputTemp"
  varInvTls11=$(grep 'TLSv1\.1' "$varSorted" | awk -F "," '{print $1 "<br>"}' | sort -V -u)
  if [ "$varInvTls11" = "" ]; then
    echo "<td>None</td>" >> "$varOutputTemp"
  else
    echo "<td><font class='ssls-orange'>$varInvTls11</font></td>" >> "$varOutputTemp"
  fi
  echo "</tr>" >> "$varOutputTemp"
  # TLSv1.1 Weak Ciphers
  echo "<tr>" >> "$varOutputTemp"
  echo "<td>TLSv1.1 Accepted with &lt;128 Bit Ciphers:</td>" >> "$varOutputTemp"
  varInvTls11Ciphers=$(grep 'TLSv1\.1' "$varSorted" | grep -E ' 0 bits| 40 bits| 56 bits| 112 bits' | awk -F "," '{print $1 "<br>"}' | sort -V -u)
  if [ "$varInvTls11Ciphers" = "" ]; then
    echo "<td>None</td>" >> "$varOutputTemp"
  else
    echo "<td><font class='ssls-red'>$varInvTls11Ciphers</font></td>" >> "$varOutputTemp"
  fi
  echo "</tr>" >> "$varOutputTemp"
  # TLSv1.1 Weak Encryption
  echo "<tr>" >> "$varOutputTemp"
  echo "<td>TLSv1.1 Accepted with ADH, AECDH, or RC4 Ciphers:</td>" >> "$varOutputTemp"
  varInvTls11Enc=$(grep 'TLSv1\.1' "$varSorted" | grep -E 'RC4|AECDH|ADH' | awk -F "," '{print $1 "<br>"}' | sort -V -u)
  if [ "$varInvTls11Enc" = "" ]; then
    echo "<td>None</td>" >> "$varOutputTemp"
  else
    echo "<td><font class='ssls-red'>$varInvTls11Enc</font></td>" >> "$varOutputTemp"
  fi
  echo "</tr>" >> "$varOutputTemp"
  # TLSv1.2 Weak Ciphers
  echo "<tr>" >> "$varOutputTemp"
  echo "<td>TLSv1.2 Accepted with &lt;128 Bit Ciphers:</td>" >> "$varOutputTemp"
  varInvTls12Ciphers=$(grep 'TLSv1\.2' "$varSorted" | grep -E ' 0 bits| 40 bits| 56 bits| 112 bits' | awk -F "," '{print $1 "<br>"}' | sort -V -u)
  if [ "$varInvTls12Ciphers" = "" ]; then
    echo "<td>None</td>" >> "$varOutputTemp"
  else
    echo "<td><font class='ssls-red'>$varInvTls12Ciphers</font></td>" >> "$varOutputTemp"
  fi
  echo "</tr>" >> "$varOutputTemp"
  # TLSv1.2 Weak Encryption
  echo "<tr>" >> "$varOutputTemp"
  echo "<td>TLSv1.2 Accepted with ADH, AECDH, or RC4 Ciphers:</td>" >> "$varOutputTemp"
  varInvTls12Enc=$(grep 'TLSv1\.2' "$varSorted" | grep -E 'RC4|AECDH|ADH' | awk -F "," '{print $1 "<br>"}' | sort -V -u)
  if [ "$varInvTls12Enc" = "" ]; then
    echo "<td>None</td>" >> "$varOutputTemp"
  else
    echo "<td><font class='ssls-red'>$varInvTls12Enc</font></td>" >> "$varOutputTemp"
  fi
  echo "</tr>" >> "$varOutputTemp"

  echo "<tr>" >> "$varOutputTemp"
  echo "<td class='heading'>Server Checks</td>" >> "$varOutputTemp"
  echo "<td class='heading'>Affected Hosts/Services</td>" >> "$varOutputTemp"
  echo "</tr>" >> "$varOutputTemp"

  # Session Renegotiation
  echo "<tr>" >> "$varOutputTemp"
  echo "<td>Insecure Session Renegotiation Supported:</td>" >> "$varOutputTemp"
  varInvSsnReneg=$(grep 'Insecure session renegotiation supported' "$varSorted" | awk -F "," '{print $1 "<br>"}' | sort -V -u)
  if [ "$varInvSsnReneg" = "" ]; then
    echo "<td>None</td>" >> "$varOutputTemp"
  else
    echo "<td><font class='ssls-red'>$varInvSsnReneg</font></td>" >> "$varOutputTemp"
  fi
  echo "</tr>" >> "$varOutputTemp"
  # Heartbleed
  echo "<tr>" >> "$varOutputTemp"
  echo "<td>Vulnerable to Heartbleed:</td>" >> "$varOutputTemp"
  varInvHeartbleed=$(grep 'TLS 1\.. vulnerable to heartbleed' "$varSorted" | awk -F "," '{print $1 "<br>"}' | sort -V -u)
  if [ "$varInvHeartbleed" = "" ]; then
    echo "<td>None</td>" >> "$varOutputTemp"
  else
    echo "<td><font class='ssls-red'>$varInvHeartbleed</font></td>" >> "$varOutputTemp"
  fi
  echo "</tr>" >> "$varOutputTemp"

  # Write end of HTML file
  echo "</table>" >> "$varOutputTemp"
  echo "</body>" >> "$varOutputTemp"
  echo "</html>" >> "$varOutputTemp"  

  echo " Done."

}

function fnCreateSummaryReport {

  echo -n "Creating HTML report..."

  # Make sure varSorted/varSortedHosts files were created
  if [ ! -f "$varSorted" ]; then echo "Error: Couldn't parse any results from '$varInFile'."; echo; return; fi
  if [ ! -f "$varSortedHosts" ]; then echo "Error: Couldn't parse any results from '$varInFile'."; echo; return; fi

  # Write beginning of HTML file
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
    if [ "$varThisHostPort" = "443" ] || [ "$varThisHostPort" = "8443" ] && [ "$varDoLinks" = "Y" ]; then
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
      fnDoCipherCell
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
      echo "<font class=ssls-normal>&#8226;Key Strength: $varGrep7</font>" >> "$varOutputTemp"
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

function fnCreateFullReport {

  echo -n "Creating HTML report..."

  # Make sure varSorted/varSortedHosts files were created
  if [ ! -f "$varSorted" ]; then echo "Error: Couldn't parse any results from '$varInFile'."; echo; return; fi
  if [ ! -f "$varSortedHosts" ]; then echo "Error: Couldn't parse any results from '$varInFile'."; echo; return; fi

  # Write beginning of HTML file
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
    if [ "$varThisHostPort" = "443" ] || [ "$varThisHostPort" = "8443" ] && [ "$varDoLinks" = "Y" ]; then
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
      fnDoCipherCell
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
      echo "<td class='FindIssuer'></td>" >> "$varOutputTemp"
    else
      varGrep5=$(grep "$varThisHost" "$varSorted"| grep 'grep5Issuer' | awk -F "," '{print "<font class=ssls-normal>" $3 "</font><br>"}')
      echo "<td class='FindIssuer'>$varGrep5</td>" >> "$varOutputTemp"
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

function fnProcessInFile {

  echo -n "Processing input file..."

  # Sanitize input file to remove sslscan color coding if necessary
  sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" "$varInFile"> $varTemp/InFile.txt
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

      varCheckCiphers=$(echo "$varLine" | grep -E '^Accepted|^Preferred')
      if [ "$varCheckCiphers" != "" ]; then
        varCiphers=$(echo "$varCheckCiphers" | awk '{print $2,"-",$3,$4,"-",$5}')
        echo "$varHost,grep4Ciphers,$varCiphers" >> "$varParsed"
        continue
      fi

      varCheckIssuers=$(echo "$varLine" | grep '^Issuer:' | grep -v '=')
      if [ "$varCheckIssuers" != "" ]; then
        echo -n "."
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
    while read varParsedIssuerLine; do
      varFindParsedIssuer=$(echo "$varParsedIssuerLine" | grep 'grep5Issuer')
      if [ "$varFindParsedIssuer" != "" ]; then
        varParsedIssuerHost=$(echo "$varFindParsedIssuer" | awk -F "," '{print $1}')
        varParsedIssuer=$(echo "$varFindParsedIssuer" | awk -F "," '{print $3}')
        varCheckParsedSubject=$(cat "$varParsed" | grep "$varParsedIssuerHost" | grep "grep9Subject" | grep "$varParsedIssuer")
        if [ "$varCheckParsedSubject" != "" ]; then
          echo "$varParsedIssuerHost,grep10IssuerMatchedSubject,$varParsedIssuer" >> "$varParsed"
        fi
      fi 
    done < "$varParsed"
    varSorted="$varTemp/sorted.txt"
    sort -V -u "$varParsed" > "$varSorted"
  fi

  if [ -f "$varUnsortedHosts" ]; then
    varSortedHosts="$varTemp/sorted-hosts.txt"
    sort -V -u "$varUnsortedHosts" > "$varSortedHosts"
  fi

  echo " Done."

}

function fnColorize {

  if [ -f "$varOutFile" ]; then rm "$varOutFile"; fi

  if [ "$varDoColor" = "N" ]; then
    mv "$varOutputTemp" "$varOutFile"
  elif [ "$varSkipColorFn" = "Y" ]; then
    mv "$varOutputTemp" "$varOutFile"
  else

    echo -n "Colorizing 'bad' results..."
 
    while read -r varLineInput; do

      varMarkThisBad="N"

      varCheckIfNewRow=$(echo "$varLineInput" | grep "<tr>")
      if [ "$varCheckIfNewRow" != "" ]; then echo -n "."; fi

      if [ "$varDoCiphers" = "accepted" ]; then
        varOutCheckWeakCiphers=$(echo "$varLineInput" | grep ' - ' | grep -E 'SSLv2|SSLv3|TLSv1\.0| 0 bits| 40 bits| 56 bits| 112 bits|RC4|AECDH|ADH')
        if [ "$varOutCheckWeakCiphers" != "" ]; then varMarkThisBad="Y"; fi      
      fi

      if [ "$varDoCiphers" = "accepted" ] && [ "$varMarkThisBad" = "N" ]; then
        varOutCheckWeakCiphers=$(echo "$varLineInput" | grep ' - ' | grep -E 'TLSv1\.1')
        if [ "$varOutCheckWeakCiphers" != "" ]; then varMarkThisBad="X"; fi      
      fi

      if [ "$varReportType" != "minimal" ] && [ "$varReportType" != "inverted" ]; then
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

        # ISSUER MATCHING SUBJECT

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
      fi

      if [ "$varMarkThisBad" = "Y" ]; then
        echo "$varLineInput" | sed 's/ssls-normal/ssls-red/g' >> "$varOutFile"
      elif [ "$varMarkThisBad" = "X" ]; then
        echo "$varLineInput" | sed 's/ssls-normal/ssls-orange/g' >> "$varOutFile"
      else
        echo "$varLineInput" >> "$varOutFile"
      fi

    done < "$varOutputTemp"
    echo " Done."
  fi

}

function fnSslScan {

  varCheckNumberOfTmpFiles=$(ls -l /tmp/sslscanalyzer-*.txt 2> /dev/null | wc -l)
  if [ "$varCheckNumberOfTmpFiles" -ge "5" ] && [ "$varQuiet" = "N" ]; then
    varDoDeleteTmp="N"
    echo "There are $varCheckNumberOfTmpFiles sslscanalyzer-*.txt files in /tmp/."
    read -p "Delete them all? [Y/N] " varDoDeleteTmp
    case "$varDoDeleteTmp" in
      y|Y)
        rm /tmp/sslscanalyzer-*.txt
        ;;
    esac
    echo
  elif [ "$varCheckNumberOfTmpFiles" -ge "5" ] && [ "$varQuiet" = "Y" ]; then
    echo "FYI: There are $varCheckNumberOfTmpFiles sslscanalyzer-*.txt files in /tmp/."
    echo
  fi

  varCheckSslScanCmd=$(sslscan 2> /dev/null)
  if [ "$varCheckSslScanCmd" != "" ]; then
    
    varCountSslScanLines=$(cat "$varInFile" | wc -l)
    echo "Running 'sslscan --show-certificate' against $varInFile ($varCountSslScanLines lines)."
    echo
    if [ "$varQuiet" = "N" ]; then read -p "Press Enter to confirm..."; echo; fi

    varSslScanResults="/tmp/sslscanalyzer-$varYMDHMS.txt"
    echo -n "Running sslscan..."
    while read varSslTarget; do
      echo -n "."
      (sslscan --show-certificate "$varSslTarget") >> "$varSslScanResults"
    done < "$varInFile"
    echo " Done."
    echo

    if [ -f "$varSslScanResults" ]; then
      varInFile="$varSslScanResults"
    else
      echo "Error: Did not create $varSslScanResults."; echo; exit
    fi

  else
    echo "Error: Could not run 'sslscan'."; echo; exit
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
    --do-sslscan )
      varDoSslScan="Y"
      ;;
    --no-links )
      varDoLinks="N"
      ;;
    * )
      echo; echo "Error: Unrecognized parameter."; fnUsage
      ;;
  esac
  shift
done

case "$varReportMode" in
  1 )
    varReportType="minimal"
    varDoCiphers="boolean"
    varSkipColorFn="Y"
    varCipherText="Weak Cipher Summary"
    ;;
  2 )
    varReportType="inverted"
    varDoCiphers="accepted"
    varSkipColorFn="Y"
    varCipherText="Accepted Ciphers"
    ;;
  3 )
    varReportType="summary"
    varDoCiphers="accepted"
    varCipherText="Accepted Ciphers"
    ;;
  4 )
    varReportType="summary"
    varDoCiphers="boolean"
    varCipherText="Weak Cipher Summary"
    ;;
  5 )
    varReportType="full"
    varDoCiphers="accepted"
    varCipherText="Accepted Ciphers"
    ;;
  6 )
    varReportType="full"
    varDoCiphers="boolean"
    varCipherText="Weak Cipher Summary"
    ;;
  * )
    varReportMode="0"
    varReportType="minimal"
    varDoCiphers="accepted"
    varCipherText="Accepted Ciphers"
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
if [ "$varDoSslScan" = "Y" ]; then fnSslScan; fi
varCountServers=$(cat "$varInFile" | grep 'Testing SSL server' | wc -l)
if [ "$varCountServers" = "0" ]; then
  echo "Error: $varInFile does not appear to contain any sslscan stdout results."
  fnUsage
else
  if [ "$varDoSslScan" = "N" ]; then echo "Converting $varInFile ($varCountServers SSL server/s) to $varOutFile."; fi
  if [ "$varDoSslScan" = "Y" ]; then echo "Converting sslscan results ($varCountServers SSL server/s) to $varOutFile."; fi
fi
echo
if [ -f "$varOutFile" ]; then echo "Warning: Continuing will overwrite $varOutFile."; echo; fi
if [ "$varQuiet" = "N" ]; then read -p "Press Enter to confirm..."; echo; fi
mkdir "$varTemp"

fnProcessInFile
if [ "$varReportType" = "minimal" ]; then
  fnCreateMinimalReport
elif [ "$varReportType" = "inverted" ]; then
  fnCreateInvertedReport
elif [ "$varReportType" = "summary" ]; then
  fnCreateSummaryReport
elif [ "$varReportType" = "full" ]; then
  fnCreateFullReport
fi
fnColorize

if [ "$varQuiet" = "N" ] && [ -f "$varOutFile" ]; then echo; read -p "Open $varOutFile using sensible-browser? [Y/N] " varOpenOutput; fi

case "$varOpenOutput" in
  y | Y)
    sensible-browser "$varOutFile" >/dev/null 2>&1 &
    ;;
esac

rm -r "$varTemp"
if [ "$varDoSslScan" = "Y" ]; then echo; echo "FYI: Original sslscan results are in $varSslScanResults"; fi
echo
echo "=========================================[ fin ]========================================="
echo

