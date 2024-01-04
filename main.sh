#!/bin/bash

main_domain="qtzfex.ru"

#######################################################################
######################### FUNCTIONS DEFINITIONS #######################
#######################################################################

prepare_file_system() {
    mkdir "$main_domain"
    cd "$main_domain"

    mkdir ./domains
    mkdir ./ip
    mkdir ./results
    mkdir ./tmp
}

get_user_subdomains() {
    read -p "Enter the path to your subdomains file (press Enter to use subfinder, massdns, and dnsgen): " user_subdomains_file
    if [ -n "$user_subdomains_file" ]; then
        cp "$user_subdomains_file" ./domains/user_subdomains.txt
    fi
}

search_and_resolve_domains() {
    if [ -f ./domains/user_subdomains.txt ]; then
        echo "Using user-provided subdomains file"
    else
        subfinder -d $main_domain > "$main_domain.log"
        cat "$main_domain.log" | cut -f1 -d, | sort -u > domains.txt
        echo $main_domain | cat - "domains.txt" > temp && mv temp "domains.txt"
    fi

    cat "$main_domain.log" | cut -f2 -d, | sort -u > ip.txt

    nslookup $main_domain | tail -n +4 | grep 'Address' | awk '{print $2}' > main_ip.txt

    cat ip.txt main_ip.txt > ip.txt
    rm -rf main_ip.txt

    comm -23 <(sort domains.txt) <(sort black_list_domains.txt) > sub_domains.txt
}

search_and_resolve_subdomains() {
    if [ ! -f ./domains/user_subdomains.txt ]; then
        cat domains.txt | dnsgen -w /usr/share/dnsrecon/subdomains-top1mil-5000.txt - | sub_domains.txt
        cat sub_domains.txt | massdns -r ../resolvers.txt -t A -o S -w massdns.out
        awk '{print $1}' massdns.out | sed 's/\.$//' | sort -u > sub_domains.txt
        awk '{print $3}' massdns.out | sort -u > sub_ip.txt
        comm -23 <(sort sub_domains.txt) <(sort black_list_domains.txt) > sub_domains.txt
    fi
}

union_domains_and_ips() {
    cat domains.txt sub_domains.txt > all_domains.txt
    cat ip.txt sub_ip.txt > all_ip.txt
}

move_files_to_folders() {
    mv ip.txt ./ip
    mv sub_ip.txt ./ip
    mv all_ip.txt ./ip

    mv domains.txt ./domains
    mv sub_domains.txt ./domains
    mv all_domains.txt ./domains

    mv massdns.out ./tmp
    mv "$main_domain.log" ./tmp
}

dig_zones() {
    mkdir ./domains/dns

    xargs -a ./domains/all_domains.txt -n 1 dig txt | grep TXT > ./domains/dns/zone_txt.txt
    xargs -a ./domains/all_domains.txt -n 1 dig mx | grep MX > ./domains/dns/zone_mx.txt
    xargs -a ./domains/all_domains.txt -n 1 dig caa | grep CAA > ./domains/dns/zone_caa.txt
    xargs -a ./domains/all_domains.txt -n 1 dig hinfo | grep HINFO > ./domains/dns/zone_hinfo.txt
    xargs -a ./domains/all_domains.txt -n 1 dig spf | grep SPF > ./domains/dns/zone_spf.txt
    xargs -a ./domains/all_domains.txt -n 1 dig key | grep KEY > ./domains/dns/zone_key.txt
}

nmap_scanner() {
    sudo xargs -a ./domains/all_domains.txt -n 1 nmap -T5 --open -sSV --min-rate=300 --max-retries=3 -F -oN all-ports-nmap-report --initial-rtt-timeout 50ms --max-rtt-timeout 100ms --min-rate 300 -Pn -oA ./results/domains_scan.txt

    xsltproc ./results/domains_scan.txt.xml -o ./results/domains_scan.txt.html

    sudo xargs -a ./ip/all_ip.txt -n 1 nmap -T5 --open -sSV --min-rate=300 --max-retries=3 -F -oN all-ports-nmap-report --initial-rtt-timeout 50ms --max-rtt-timeout 100ms --min-rate 300 -Pn -oA ./results/ip_scan.txt

    xsltproc ./results/ip_scan.txt.xml -o ./results/ip_scan.txt.html
}

#######################################################################
######################### SCRIPT EXECUTION ############################
#######################################################################

prepare_file_system
get_user_subdomains
search_and_resolve_domains
search_and_resolve_subdomains
union_domains_and_ips
move_files_to_folders
dig_zones
nmap_scanner

### Add other functions for vulnerability scanning as needed
