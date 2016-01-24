# sslscanalyzer
Shell script for converting an input file containing one or more `sslscan` results into HTML tables.

# Usage
```
./sslscanalyzer.sh [input file] [options]
```

* **[input file]** is required and must be the first parameter. It does not matter if the color-coded `sslscan` output was used or not.
* **-q** - "Quiet" option. Disables the confirmation prompt at the beginning of the script, as well as the prompt that asks you if you want to open the HTML file using `sensible-browser`.
* **--all-ciphers** - By default, the HTML report will list weak ciphers. This option will override that, to list all accepted ciphers.
* **--full** - By default, "short" output condenses session renegotiation, compression, and heartbleed checks into an "SSL Server Checks" column, and certificate details are condensed into another. This option breaks out each value/check into a separate column. Weak/supported ciphers are always their own column.
