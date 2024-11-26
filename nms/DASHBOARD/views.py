from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.shortcuts import render, redirect
import subprocess
import platform
import logging
import socket
from prettytable import PrettyTable

from DNS.models import DNS

logger = logging.getLogger(__name__)

# Import necessary modules from pysnmp
from pysnmp.hlapi import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    nextCmd,
    UsmUserData,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmAesCfb128Protocol,
    usmDESPrivProtocol,
)


@login_required
def logout_view(request):
    logout(request)
    return redirect("login")  # Replace 'login' with the name of your login URL


@login_required
def ping_operation(request):
    if request.method == "POST":
        ip_address = request.POST.get("ip_address")
        enable_ping = request.POST.get("enable_ping")
        verbose_ping = request.POST.get("verbose_ping")
        traceroute = request.POST.get("traceroute")
        dns_lookup = request.POST.get("dns_lookup")
        snmp_walk = request.POST.get("snmp_walk")
        # Get all DNS names as a list
        dns_names = list(DNS.objects.values_list("dns_name", flat=True))

        # Check if IP address or domain name is provided
        if not ip_address:
            return render(
                request,
                "ping.html",
                {"error_message": "Please provide an IP address or domain name."},
            )

        # Detect the operating system
        os_name = platform.system()
        results = []

        try:
            # Create a PrettyTable for formatting output
            table = PrettyTable()
            table.field_names = ["Operation", "Result"]

            # Perform Enable Ping
            if enable_ping:
                if os_name == "Windows":
                    command = ["ping", "-n", "1", ip_address]
                else:
                    command = ["ping", "-c", "1", ip_address]

                logger.info(f"Pinging {ip_address} with basic ping.")
                response = subprocess.run(command, capture_output=True, text=True)
                ping_result = (
                    "Device is alive"
                    if response.returncode == 0
                    else "Device is unreachable"
                )
                table.add_row(["Enable Ping", ping_result])

            # Perform Verbose Ping
            if verbose_ping:
                if os_name == "Windows":
                    command = ["ping", "-n", "4", ip_address]
                else:
                    command = ["ping", "-c", "4", ip_address]

                logger.info(f"Pinging {ip_address} with verbose ping.")
                response = subprocess.run(command, capture_output=True, text=True)
                verbose_result = (
                    response.stdout
                    if response.returncode == 0
                    else "Verbose Ping failed."
                )
                table.add_row(["Verbose Ping Result", verbose_result])

            # Perform Traceroute
            if traceroute:
                if os_name == "Windows":
                    command = ["tracert", ip_address]
                else:
                    command = ["traceroute", ip_address]

                logger.info(f"Running traceroute for {ip_address}.")
                response = subprocess.run(command, capture_output=True, text=True)
                traceroute_result = (
                    response.stdout
                    if response.returncode == 0
                    else "Traceroute failed."
                )
                table.add_row(["Traceroute Result", traceroute_result])

            # Perform DNS Lookup
            if dns_lookup:
                ip_address_d = socket.gethostbyname(ip_address)
                if ip_address_d in dns_names:
                    logger.info("IP address exists in DNS records.")
                    if os_name == "Windows":
                        command = ["nslookup", ip_address]
                    else:
                        command = ["dig", ip_address]
                    response = subprocess.run(command, capture_output=True, text=True)
                    dns_result = (
                        response.stdout
                        if response.returncode == 0
                        else "DNS Lookup failed."
                    )
                    table.add_row(["DNS Lookup Result", dns_result])
                else:
                    table.add_row(
                        ["DNS Lookup Result", "DNS IP did not match the record."]
                    )

            # Perform SNMP Walk
            if snmp_walk:
                snmp_port = request.POST.get("snmp_port", 161)
                snmp_version = request.POST.get("snmp_version")
                read_community_string = request.POST.get(
                    "read_community_string", "public"
                )
                username = request.POST.get("username")
                password = request.POST.get("password")
                authentication_type = request.POST.get("authentication_type", "SHA")
                encryption_type = request.POST.get("encryption_type", "AES")
                encryption_key = request.POST.get("encryption_key")
                context_name = request.POST.get("context_name", "")
                oid = request.POST.get("oid", "1.3.6.1")

                try:
                    # Handle SNMP Version and append results
                    snmp_result = []
                    if snmp_version in ["1", "2c"]:
                        for (
                            errorIndication,
                            errorStatus,
                            errorIndex,
                            varBinds,
                        ) in nextCmd(
                            SnmpEngine(),
                            CommunityData(
                                read_community_string,
                                mpModel=0 if snmp_version == "1" else 1,
                            ),
                            UdpTransportTarget((ip_address, int(snmp_port))),
                            ContextData(),
                            ObjectType(ObjectIdentity(oid)),
                            lexicographicMode=False,
                        ):
                            if errorIndication:
                                snmp_result.append(f"Error: {errorIndication}")
                                break
                            elif errorStatus:
                                snmp_result.append(
                                    f"Error: {errorStatus.prettyPrint()} at {errorIndex}"
                                )
                                break
                            else:
                                for varBind in varBinds:
                                    snmp_result.append(f"{varBind[0]} = {varBind[1]}")
                        table.add_row(["SNMP Walk Result", "\n".join(snmp_result)])

                    elif snmp_version == "3":
                        auth_protocol = usmNoAuthProtocol
                        priv_protocol = usmNoPrivProtocol
                        if authentication_type == "MD5":
                            auth_protocol = usmHMACMD5AuthProtocol
                        elif authentication_type == "SHA":
                            auth_protocol = usmHMACSHAAuthProtocol
                        if encryption_type == "AES":
                            priv_protocol = usmAesCfb128Protocol
                        elif encryption_type == "DES":
                            priv_protocol = usmDESPrivProtocol

                        result = []
                        for (
                            errorIndication,
                            errorStatus,
                            errorIndex,
                            varBinds,
                        ) in nextCmd(
                            SnmpEngine(),
                            UsmUserData(
                                username,
                                password,
                                encryption_key,
                                authProtocol=auth_protocol,
                                privProtocol=priv_protocol,
                            ),
                            UdpTransportTarget((ip_address, int(snmp_port))),
                            ContextData(context_name),
                            ObjectType(ObjectIdentity(oid)),
                            lexicographicMode=False,
                        ):
                            if errorIndication:
                                result.append(f"Error: {errorIndication}")
                                break
                            elif errorStatus:
                                result.append(
                                    f"Error: {errorStatus.prettyPrint()} at {errorIndex}"
                                )
                                break
                            else:
                                for varBind in varBinds:
                                    result.append(f"{varBind[0]} = {varBind[1]}")
                        table.add_row(["SNMP Walk Result", "\n".join(result)])

                    else:
                        table.add_row(
                            [
                                "SNMP Walk Result",
                                f"Unsupported SNMP version: {snmp_version}",
                            ]
                        )

                except Exception as e:
                    logging.error(
                        f"An error occurred while performing SNMP walk: {str(e)}"
                    )
                    table.add_row(["SNMP Walk Result", f"Error: {str(e)}"])

            return render(request, "ping.html", {"table": table})

        except Exception as e:
            error_message = f"An error occurred: {str(e)}"
            logger.error(f"Network operation failed: {error_message}")
            return render(request, "ping.html", {"error_message": error_message})
    else:
        return render(request, "ping.html")
