import socket
import zlib
import os
import keyboard
import struct
import random
import string
import ntplib
import dns.resolver
import dns.exception
from socket import gaierror
import threading
import time
from time import ctime
import requests
import datetime


def echo_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = '127.0.0.1'
    server_port = 12345

    try:
        sock.connect((server_address, server_port))
        message = 'Hello Server'
        sock.sendall(message.encode())

        response = sock.recv(1024)
        return f"sent message {message}", f"Received message: {response.decode()}"
    finally:
        sock.close()


def timestamped_print(*args, **kwargs):
    """
    Custom print function that adds a timestamp to the beginning of the message.
    Args:
    *args: Variable length argument list.
    **kwargs: Arbitrary keyword arguments. These are passed to the built-in
    print function.
    """
    # Get the current time and format it
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Print the timestamp followed by the original message
    print(f"[{timestamp}]: ", *args, **kwargs)


def check_udp_port(ip_address: str, port: int, timeout: int = 3):
    """
    Checks the status of a specific UDP port on a given IP address.

    Args:
    ip_address (str): The IP address of the target server.
    port (int): The UDP port number to check.
    timeout (int): The timeout duration in seconds for the socket operation. Default is 3 seconds.

    Returns:
    tuple: A tuple containing a boolean and a string.
           The boolean is True if the port is open (or if the status is uncertain), False if the port is definitely closed.
           The string provides a description of the port status.

    Description:
    This function attempts to send a UDP packet to the specified port on the given IP address.
    Since UDP is a connectionless protocol, the function can't definitively determine if the port is open.
    It can only confirm if the port is closed, typically indicated by an ICMP 'Destination Unreachable' response.
    """

    try:
        # Create a socket object using the AF_INET address family (IPv4) and SOCK_DGRAM socket type (UDP).
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Set a timeout for the socket to avoid waiting indefinitely.
            s.settimeout(timeout)

            # Send a dummy packet to the specified IP address and port.
            # As UDP is connectionless, this does not establish a connection but merely sends the packet.
            s.sendto(b'', (ip_address, port))

            try:
                # Try to receive data from the socket.
                # If an ICMP 'Destination Unreachable' message is received, the port is considered closed.
                s.recvfrom(1024)
                return False, f"Port {port} on {ip_address} is closed."

            except socket.timeout:
                # If a timeout occurs, it's uncertain whether the port is open or closed, as no response is received.
                return True, f"Port {port} on {ip_address} is open or no response received."

    except Exception as e:
        # Catch any other exceptions and return a general failure message along with the exception raised.
        return False, f"Failed to check UDP port {port} on {ip_address} due to an error: {e}"


def check_tcp_port(ip_address: str, port: int):
    """
    Checks the status of a specific TCP port on a given IP address.

    Args:
    ip_address (str): The IP address of the target server.
    port (int): The TCP port number to check.

    Returns:
    tuple: A tuple containing a boolean and a string.
           The boolean is True if the port is open, False otherwise.
           The string provides a description of the port status.

    Description:
    This function attempts to establish a TCP connection to the specified port on the given IP address.
    If the connection is successful, it means the port is open; otherwise, the port is considered closed or unreachable.
    """

    try:
        # Create a socket object using the AF_INET address family (IPv4) and SOCK_STREAM socket type (TCP).
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set a timeout for the socket to avoid waiting indefinitely. Here, 3 seconds is used as a reasonable
            # timeout duration.
            s.settimeout(3)

            # Attempt to connect to the specified IP address and port.
            # If the connection is successful, the port is open.
            s.connect((ip_address, port))
            response = s.recv(1024)
            return True, f"Port {port} on {ip_address} is open.", f"Received response message: {response.decode()}"

    except socket.timeout:
        # If a timeout occurs, it means the connection attempt took too long, implying the port might be filtered or the
        # server is slow to respond.
        return False, f"Port {port} on {ip_address} timed out.", "No response"

    except socket.error:
        # If a socket error occurs, it generally means the port is closed or not reachable.
        return False, f"Port {port} on {ip_address} is closed or not reachable.", "No response"

    except Exception as e:
        # Catch any other exceptions and return a general failure message along with the exception raised.
        return False, f"Failed to check port {port} on {ip_address} due to an error: {e}", "No response"


def check_ntp_server(server: str):
    """
    Checks if an NTP server is up and returns its status and time.

    Args:
    server (str): The hostname or IP address of the NTP server to check.

    Returns:
    Tuple[bool, Optional[str]]: A tuple containing a boolean indicating the server status
                                 (True if up, False if down) and the current time as a string
                                 if the server is up, or None if it's down.
    """
    # Create an NTP client instance
    client = ntplib.NTPClient()

    try:
        # Request time from the NTP server
        # 'version=3' specifies the NTP version to use for the request
        response = client.request(server, version=3)

        # If request is successful, return True and the server time
        # 'ctime' converts the time in seconds since the epoch to a readable format
        return True, ctime(response.tx_time)
    except (ntplib.NTPException, gaierror):
        # If an exception occurs (server is down or unreachable), return False and None
        return False, None


def check_dns_server_status(server, query, record_type) -> (bool, str):
    """
    Check if a DNS server is up and return the DNS query results for a specified domain and record type.

    :param server: DNS server name or IP address
    :param query: Domain name to query
    :param record_type: Type of DNS record (e.g., 'A', 'AAAA', 'MX', 'CNAME')
    :return: Tuple (status, query_results)
    """
    try:
        # Set the DNS resolver to use the specified server
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [socket.gethostbyname(server)]

        # Perform a DNS query for the specified domain and record type
        query_results = resolver.resolve(query, record_type)
        results = [str(rdata) for rdata in query_results]

        return True, results

    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer, socket.gaierror) as e:
        # Return False if there's an exception (server down, query failed, or record type not found)
        return False, str(e)


def calculate_icmp_checksum(data: bytes) -> int:
    """
    Calculate the checksum for the ICMP packet.

    The checksum is calculated by summing the 16-bit words of the entire packet,
    carrying any overflow bits around, and then complementing the result.

    Args:
    data (bytes): The data for which the checksum is to be calculated.

    Returns:
    int: The calculated checksum.
    """

    s: int = 0  # Initialize the sum to 0.

    # Iterate over the data in 16-bit (2-byte) chunks.
    for i in range(0, len(data), 2):
        # Combine two adjacent bytes (8-bits each) into one 16-bit word.
        # data[i] is the high byte, shifted left by 8 bits.
        # data[i + 1] is the low byte, added to the high byte.
        # This forms one 16-bit word for each pair of bytes.
        w: int = (data[i] << 8) + (data[i + 1])
        s += w  # Add the 16-bit word to the sum.

    # Add the overflow back into the sum.
    # If the sum is larger than 16 bits, the overflow will be in the higher bits.
    # (s >> 16) extracts the overflow by shifting right by 16 bits.
    # (s & 0xffff) keeps only the lower 16 bits of the sum.
    # The two parts are then added together.
    s = (s >> 16) + (s & 0xffff)

    # Complement the result.
    # ~s performs a bitwise complement (inverting all the bits).
    # & 0xffff ensures the result is a 16-bit value by masking the higher bits.
    s = ~s & 0xffff

    return s  # Return the calculated checksum.


def create_icmp_packet(icmp_type: int = 8, icmp_code: int = 0, sequence_number: int = 1, data_size: int = 192):
    """
    Creates an ICMP (Internet Control Message Protocol) packet with specified parameters.

    Args:
    icmp_type (int): The type of the ICMP packet. Default is 8 (Echo Request).
    icmp_code (int): The code of the ICMP packet. Default is 0.
    sequence_number (int): The sequence number of the ICMP packet. Default is 1.
    data_size (int): The size of the data payload in the ICMP packet. Default is 192 bytes.

    Returns:
    bytes: A bytes object representing the complete ICMP packet.

    Description:
    The function generates a unique ICMP packet by combining the specified ICMP type, code, and sequence number
    with a data payload of a specified size. It calculates a checksum for the packet and ensures that the packet
    is in the correct format for network transmission.
    """

    # Get the current thread identifier and process identifier.
    # These are used to create a unique ICMP identifier.
    thread_id = threading.get_ident()
    process_id = os.getpid()

    # Generate a unique ICMP identifier using CRC32 over the concatenation of thread_id and process_id.
    # The & 0xffff ensures the result is within the range of an unsigned 16-bit integer (0-65535).
    icmp_id = zlib.crc32(f"{thread_id}{process_id}".encode()) & 0xffff

    # Pack the ICMP header fields into a bytes object.
    # 'bbHHh' is the format string for struct.pack, which means:
    # b - signed char (1 byte) for ICMP type
    # b - signed char (1 byte) for ICMP code
    # H - unsigned short (2 bytes) for checksum, initially set to 0
    # H - unsigned short (2 bytes) for ICMP identifier
    # h - short (2 bytes) for sequence number
    header: bytes = struct.pack('bbHHh', icmp_type, icmp_code, 0, icmp_id, sequence_number)

    # Create the data payload for the ICMP packet.
    # It's a sequence of a single randomly chosen alphanumeric character (uppercase or lowercase),
    # repeated to match the total length specified by data_size.
    random_char: str = random.choice(string.ascii_letters + string.digits)
    data: bytes = (random_char * data_size).encode()

    # Calculate the checksum of the header and data.
    chksum: int = calculate_icmp_checksum(header + data)

    # Repack the header with the correct checksum.
    # socket.htons ensures the checksum is in network byte order.
    header = struct.pack('bbHHh', icmp_type, icmp_code, socket.htons(chksum), icmp_id, sequence_number)

    # Return the complete ICMP packet by concatenating the header and data.
    return header + data


def ping(host: str, ttl: int = 64, timeout: int = 1, sequence_number: int = 1):
    """
    Send an ICMP Echo Request to a specified host and measure the round-trip time.

    This function creates a raw socket to send an ICMP Echo Request packet to the given host.
    It then waits for an Echo Reply, measuring the time taken for the round trip. If the
    specified timeout is exceeded before receiving a reply, the function returns None for the ping time.

    Args:
    host (str): The IP address or hostname of the target host.
    ttl (int): Time-To-Live for the ICMP packet. Determines how many hops (routers) the packet can pass through.
    timeout (int): The time in seconds that the function will wait for a reply before giving up.
    sequence_number (int): The sequence number for the ICMP packet. Useful for matching requests with replies.

    Returns:
    Tuple[Any, float] | Tuple[Any, None]: A tuple containing the address of the replier and the total ping time in
    milliseconds.
    If the request times out, the function returns None for the ping time. The address part of the tuple is also None if
     no reply is received.
    """

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        # Set the Time-To-Live (TTL) for the ICMP packet.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        # Set the timeout for the socket's blocking operations (e.g., recvfrom).
        sock.settimeout(timeout)

        packet: bytes = create_icmp_packet(icmp_type=8, icmp_code=0, sequence_number=sequence_number)

        sock.sendto(packet, (host, 1))


        start: float = time.time()

        try:
            # Wait to receive data from the socket (up to 1024 bytes).
            # This will be the ICMP Echo Reply if the target host is reachable.
            data, addr = sock.recvfrom(1024)

            # Record the time when the reply is received.
            end: float = time.time()

            # Calculate the round-trip time in milliseconds.
            total_ping_time = (end - start) * 1000

            # Return the address of the replier and the total ping time.
            return addr, total_ping_time
        except socket.timeout:
            # If no reply is received within the timeout period, return None for the ping time.
            return None, None


def traceroute(host: str, max_hops: int = 30, pings_per_hop: int = 1, verbose: bool = False):
    """
    Perform a traceroute to the specified host, with multiple pings per hop.

    Args:
    host (str): The IP address or hostname of the target host.
    max_hops (int): Maximum number of hops to try before stopping.
    pings_per_hop (int): Number of pings to perform at each hop.
    verbose (bool): If True, print additional details during execution.

    Returns:
    str: The results of the traceroute, including statistics for each hop.
    """
    # Header row for the results. Each column is formatted for alignment and width.
    results = [f"{'Hop':>3} {'Address':<15} {'Min (ms)':>8}   {'Avg (ms)':>8}   {'Max (ms)':>8}   {'Count':>5}"]

    # Loop through each TTL (Time-To-Live) value from 1 to max_hops.
    for ttl in range(1, max_hops + 1):
        # Print verbose output if enabled.
        if verbose:
            print(f"pinging {host} with ttl: {ttl}")

        # List to store ping response times for the current TTL.
        ping_times = []

        # Perform pings_per_hop number of pings for the current TTL.
        for _ in range(pings_per_hop):

            addr, response = ping(host, ttl=ttl, sequence_number=ttl)

            if response is not None:
                ping_times.append(response)

        # If there are valid ping responses, calculate and format the statistics.
        if ping_times:
            min_time = min(ping_times)  # Minimum ping time.
            avg_time = sum(ping_times) / len(ping_times)  # Average ping time.
            max_time = max(ping_times)  # Maximum ping time.
            count = len(ping_times)  # Count of successful pings.

            # Append the formatted results for this TTL
            results.append(f"{ttl:>3} {addr[0] if addr else '*':<15} {min_time:>8.2f}ms {avg_time:>8.2f}ms "
                           f"{max_time:>8.2f}ms {count:>5}")
        else:
            # If no valid responses, append a row of asterisks and zero count.
            results.append(f"{ttl:>3} {'*':<15} {'*':>8}   {'*':>8}   {'*':>8}   {0:>5}")

        # Print the last entry in the results if verbose mode is enabled.
        if verbose and results:
            print(f"\tResult: {results[-1]}")

        # If the address of the response matches the target host, stop the traceroute.
        if addr and addr[0] == host:
            break

    return '\n'.join(results)


def check_server_https(url: str, timeout: int = 5):
    """
    Check if an HTTPS server is up by making a request to the provided URL.

    This function attempts to connect to a web server using the specified URL with HTTPS.
    It returns a tuple containing a boolean indicating whether the server is up,
    the HTTP status code returned by the server, and a descriptive message.

    :param url: URL of the server (including https://)
    :param timeout: Timeout for the request in seconds. Default is 5 seconds.
    :return: Tuple (True/False for server status, status code, description)
    """
    try:

        headers: dict = {'User-Agent': 'Mozilla/5.0'}

        response: requests.Response = requests.get(url, headers=headers, timeout=timeout)

        is_up: bool = response.status_code < 400

        # Returning a tuple: (server status, status code, descriptive message)
        return is_up, response.status_code, "Server is up"

    except requests.ConnectionError:
        # This exception is raised for network-related errors, like DNS failure or refused connection.
        return False, None, "Connection error"

    except requests.Timeout:
        # This exception is raised if the server does not send any data in the allotted time (specified by timeout).
        return False, None, "Timeout occurred"

    except requests.RequestException as e:

        return False, None, f"Error during request: {e}"


def check_server_http(url: str):
    """
    Check if an HTTP server is up by making a request to the provided URL.

    This function attempts to connect to a web server using the specified URL.
    It returns a tuple containing a boolean indicating whether the server is up,
    and the HTTP status code returned by the server.

    :param url: URL of the server (including http://)
    :return: Tuple (True/False, status code)
             True if server is up (status code < 400), False otherwise
    """
    try:
        # Making a GET request to the server
        response: requests.Response = requests.get(url)

        is_up: bool = response.status_code < 400

        # Returning a tuple: (True/False, status code)
        # True if the server is up, False if an exception occurs (see except block)
        return is_up, response.status_code

    except requests.RequestException:

        return False, None


def on_key_press(keyboard_event):
    if keyboard_event.name == "esc":
        print("Exiting Monitoring\n\n")
        global liveMonitoring
        liveMonitoring = False


def main():
    print("Welcome to my network monitoring application By Rajan Patel!")
    monitoring_list = []

    continueLoop = True
    while continueLoop:
        print("----------Services Currently Monitored-------------")
        # for loop to run through added services that are to be monitored
        for i in range(len(monitoring_list)):
            if monitoring_list[i][0] == "http":
                print(f"{i+1} - Service: http | Address: {monitoring_list[i][1]}")
            if monitoring_list[i][0] == "https":
                print(f"{i + 1} - Service: https | Address: {monitoring_list[i][1]}")
            if monitoring_list[i][0] == "ICMP":
                print(f"{i + 1} - Service: ICMP | Address: {monitoring_list[i][1]} | Tool: {monitoring_list[i][2]}")
            if monitoring_list[i][0] == "DNS":
                print(f"{i + 1} - Service: DNS | Address: {monitoring_list[i][1]} | Query: {monitoring_list[i][2]} | "
                      f"Record Type: {monitoring_list[i][3]}")
            if monitoring_list[i][0] == "NTP":
                print(f"{i + 1} - Service: NTP | Address: {monitoring_list[i][1]}")
            if monitoring_list[i][0] == "TCP":
                print(f"{i + 1} - Service: TCP | Address: {monitoring_list[i][1]} | Port: {monitoring_list[i][2]}")
            if monitoring_list[i][0] == "UDP":
                print(f"{i + 1} - Service: UDP | Address: {monitoring_list[i][1]} | Port: {monitoring_list[i][2]}")
            if monitoring_list[i][0] == "Local Echo Server":
                print(f"{i + 1} - Service: Local Echo Server | Address: {monitoring_list[i][1]} | Port: {monitoring_list[i][2]}")
        print("---------------------------------------------------")
        print("What would you like to monitor?\n 1:HTTP\n 2:HTTPS\n 3:ICMP\n 4:DNS\n"
              " 5:NTP\n 6:TCP\n 7:UDP\n 8:Local Echo Server\n 9:Start Monitoring\n 10:Clear list\n 11:exit program\n")
        selection = input("Please enter a number between 0-11: ")
        if selection == "1":  # adds http into monitoring list
            info = []
            info.append("http")
            address = input(" Please enter a URL with 'http://': ")
            info.append(address)
            monitoring_list.append(info)
        elif selection == "2":  # adds https into monitoring list
            info = []
            info.append("https")
            address = input(" Please enter a URL with 'https://': ")
            info.append(address)
            monitoring_list.append(info)
        elif selection == "3":  # adds ICMP into monitoring list
            info = []
            info.append("ICMP")
            address = input(" Please enter the IP address or Hostname of target: ")
            info.append(address)
            tool = input(" Please enter 1 if you would like a Ping to the target or enter 2 for a traceroute: ")
            if tool == "1":
                info.append("Ping")
            elif tool == "2":
                info.append("Traceroute")
            monitoring_list.append(info)
        elif selection == "4":  # adds DNS into monitoring list
            info = []
            info.append("DNS")
            address = input(" Please enter the DNS server name or IP address: ")
            info.append(address)
            query = input(" Please enter the domain name to query: ")
            info.append(query)
            record_type = input(" Please select record type:\n  1: A\n  2: AAAA\n  3: MX\n  4:CNAME\n   :")
            if record_type == "1":
                info.append("A")
            elif record_type == "2":
                info.append("AAAA")
            elif record_type == "3":
                info.append("MX")
            elif record_type == "4":
                info.append("CNAME")
            monitoring_list.append(info)
        elif selection == "5":  # adds NTP into monitoring list
            info = []
            info.append("NTP")
            address = input(" Please enter the hostname or IP address of the NTP server to check: ")
            info.append(address)
            monitoring_list.append(info)
        elif selection == "6":  # adds TCP into monitoring list
            info = []
            info.append("TCP")
            address = input(" Please enter the IP address of the target server: ")
            info.append(address)
            port = input( "Please enter the TCP port number to check: ")
            info.append(int(port))
            monitoring_list.append(info)
        elif selection == "7":  # adds UDP into monitoring list
            info = []
            info.append("UDP")
            address = input(" Please enter the IP address of the target server: ")
            info.append(address)
            port = input( "Please enter the UDP port number to check: ")
            info.append(int(port))
            monitoring_list.append(info)
        elif selection == "8":
            info = []
            info.append("Local Echo Server")
            address = "127.0.0.1"
            info.append(address)
            port = 12345
            info.append(port)
            monitoring_list.append(info)
        elif selection == "9":  # starts monitoring loop
            intervalFrequency = input("Please input frequency of monitoring (seconds): ")  # asks user to set the
            # frequency
            numbericalFreq = int(intervalFrequency)  # changes frequency value inputted into a int from str
            global liveMonitoring
            liveMonitoring = True
            keyboard.on_press_key('esc', on_key_press)
            try:
                while liveMonitoring:
                    print("\nPress 'esc' to exit live monitoring.")
                    for i in range(len(monitoring_list)):
                        if monitoring_list[i][0] == "http":
                            http_server_status, http_server_response_code = check_server_http(monitoring_list[i][1])
                            timestamped_print(f"HTTP URL: {monitoring_list[i][1]}, HTTP server status: {http_server_status}, Status "
                                  f"Code:{http_server_response_code if http_server_response_code is not None else 'N/A'}")
                        if monitoring_list[i][0] == "https":
                            https_server_status, https_server_response_code = check_server_http(monitoring_list[i][1])
                            timestamped_print(f"HTTPS URL: {monitoring_list[i][1]}, HTTPS server status: {https_server_status}, "
                                  f"Status ""Code:{https_server_response_code if https_server_response_code is not None"
                                  "else 'N/A'}")
                        if monitoring_list[i][0] == "ICMP":
                            if monitoring_list[i][2] == "Ping":
                                ping_addr, ping_time = ping(monitoring_list[i][1])
                                timestamped_print(f"ICMP (ping): {ping_addr[0]} - {ping_time:.2f} ms" if (
                                            ping_addr and ping_time is not None) else " Request timed out or no reply "
                                                                                      "received")
                            if monitoring_list[i][2] == "Traceroute":
                                print("Traceroute: ")
                                timestamped_print(traceroute(monitoring_list[i][1]))
                        if monitoring_list[i][0] == "DNS":
                            dns_server_status, dns_query_results = check_dns_server_status(monitoring_list[i][1],
                                                                                           monitoring_list[i][2],
                                                                                           monitoring_list[i][3])
                            timestamped_print(f"DNS Server: {monitoring_list[i][1]}, Status: {dns_server_status}, "
                                  f"{monitoring_list[i][3]} Records Results: {dns_query_results}")
                        if monitoring_list[i][0] == "NTP":
                            ntp_server_status, ntp_server_time = check_ntp_server(monitoring_list[i][1])
                            timestamped_print(
                                f"{monitoring_list[i][1]} is up. Time: {ntp_server_time}" if ntp_server_status else
                                f"{monitoring_list[i][1]} is down.")
                        if monitoring_list[i][0] == "TCP":
                            tcp_port_status, tcp_port_description, tcp_response = check_tcp_port(monitoring_list[i][1],
                                                                                   monitoring_list[i][2])
                            timestamped_print(f"Server: {monitoring_list[i][1]}, TCP Port: {monitoring_list[i][2]}, "
                                  f"TCP Port Status: {tcp_port_status}, Description: {tcp_port_description}, Response: "
                                              f"{tcp_response}")
                        if monitoring_list[i][0] == "UDP":
                            udp_port_status, udp_port_description = check_udp_port(monitoring_list[i][1],
                                                                                   monitoring_list[i][2])
                            timestamped_print(f"Server: {monitoring_list[i][1]}, UDP Port: {monitoring_list[i][2]}, "
                                  f"UDP Port Status: {udp_port_status}, Description: {udp_port_description}")
                        if monitoring_list[i][0] == "Local Echo Server":
                            sentMSG, responseMSG = echo_client()
                            timestamped_print(sentMSG, responseMSG)

                    time.sleep(int(numbericalFreq))
            finally:
                keyboard.unhook_all()
        elif selection == "10":
            monitoring_list = []
        elif selection == "11":
            print("Exiting program")
            continueLoop = False


if __name__ == "__main__":
    main()
