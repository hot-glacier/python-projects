import socket
import ssl
import sys
import urlparse

redirect_max = 5

def send_request(URL, redirects=0):
    # Make sure the redirect count hasn't been met, exit if it has
    if redirects > redirect_max:
        print("Error: Too many redirects, exiting...")
        return

    # This will check to see if there is a http:// or https:// scheme in the url, and add http:// if not
    if not URL.startswith('http://') and not URL.startswith('https://'):
        URL = 'http://' + URL

    # Parse the URL passed in and set the variables
    parsed_URL = urlparse.urlparse(URL)
    host = parsed_URL.hostname
    port = 80 if parsed_URL.scheme == 'http' else 443
    path = parsed_URL.path or '/'
    if parsed_URL.query:
        path += '?' + parsed_URL.query

    # Check if the hostname is in a valid form, exit if not
    try:
        proper_host = socket.gethostbyname(host)
    except socket.gaierror as e:
        print("Error: Invalid hostname {}.".format(host))
        return

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Attempt connection to the host
    try:
        s.connect((proper_host, port))
    except socket.error as e:
        print("Error: Unable to connect to {}: {}".format(host, e))
        return
    
    print("Successfully connected to {}://{}.".format(parsed_URL.scheme,host))

    # Check if scheme is https, if yes wrap the socket
    if parsed_URL.scheme == 'https':
        context = ssl.create_default_context()
        s = context.wrap_socket(s, server_hostname=host)

    # Set the parameters of the request
    request = (
        "GET {} HTTP/1.1\r\n"
        "Host: {}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).format(path, host)
    
    # Send the request
    s.sendall(request)
    
    # Get the response and close the connection
    data = s.recv(10000)
    s.close()

    # Parse the response and extract the headers (body not needed)
    parts = data.split('\r\n\r\n', 1)
    headers_full = parts[0]
    headers_lines = headers_full.split('\r\n')
    
    # Extract the status code from the headers
    status_line = headers_lines[0]
    status_code = int(status_line.split(' ')[1])

    # Handle redirects due to code 301 or 302
    if status_code in (301, 302):
        location = None
        # Parse the headers, find the location line, and store the new location
        for header in headers_lines[1:]:
            if header.lower().startswith('location:'):
                location = header.split(':', 1)[1].strip()
                break

        # If there is a location, recursively call send_request, else return
        if location:
            print("Redirecting to: {}".format(location))
            return send_request(location, redirects + 1)
        else:
            print("Redirect received, but no Location header found.")
            return

    # Print only headers, not body
    print("\n---Headers---")
    print(headers_full)
    print("\nBody content received but not shown.")

    # Extract any cookies from the headers, store in an array
    cookies = []
    for header in headers_lines[1:]:
        if header.lower().startswith('set-cookie:'):
            cookies.append(header[len('Set-Cookie:'):].strip()) # Append the header without the 'Set-Cookie:'

    print("\n---Summary---")
    print("Website: {}".format(host))


    # Print whether the server supports HTTP/2 protocol or not
    if http2_supported:
        print("1. Supports http2: yes")
    else:
        print("1. Supports http2: no")

    # Print any cookies and their relevant values (name, expiration date, domain)
    if cookies:
        print("2. List of Cookies:")
        
        # Parse the list of cookies
        for i, cookie_string in enumerate(cookies):
            cookie = [p.strip() for p in cookie_string.split(';')] # Separating the individual cookies and removing whitespace
            name = cookie[0].split('=', 1)[0] if '=' in cookie[0] else cookie[0] # Extract the name of the cookie (all text before the first '=' symbol)
            expires = None
            domain = None

            # Parse the rest of each cookie to find expiration time and domain, if they exist
            for attr in cookie[1:]:
                if attr.lower().startswith('expires='):
                    expires = attr[len('expires='):]
                elif attr.lower().startswith('domain='):
                    domain = attr[len('domain='):]
            
            # Print out the cookie names and their expiration time and domain, if they exist
            if i == 0:
                print("cookie name: {}, ".format(name)),
            else:
                print("\ncookie name: {}, ".format(name)),
            if expires:
                print("expire time: {}, ".format(expires)),
            if domain:
                print("domain name: {}, ".format(domain)),
    else:
        print("2. List of Cookies: \nNo cookies were set by the server."),

    # Check if password protected
    if status_code == 401:
        print("\n3. Password-protected: yes")
    else:
        print("\n3. Password-protected: no")


# This function checks if the server supports HTTP/2 protocol without sending any requests
# Doing this prevents the responses from being a format that cannot be parsed by this code
def check_http2(host, port=443):
    context = ssl.create_default_context()
    context.set_alpn_protocols(['h2', 'http/1.1']) #Checking for protocols HTTP/2 and HTTP/1.1
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        ss = context.wrap_socket(s, server_hostname=host)
        protocol = ss.selected_alpn_protocol()
        ss.close()
        return protocol == 'h2' #Return True if the protocol is 'h2' (HTTP/2)
    except Exception as e:
        print("Error checking HTTP/2 support: {}".format(e))
        return False


# To begin, the program first checks if the correct number of arguments were passed in.
# If not, print instructions on how to use the program

if len(sys.argv) != 2:
    print("Incorrect usage. Please type the command as follows: python webTester.py (URL)")
    print("Example: python webTester.py www.uvic.ca")
else:
    http2_supported = False     #Set HTTP/2 support to a default state of False (only supports HTTP/1.1)
    
    # Parse the passed in URL, add 'http://' if needed, set the host
    url = sys.argv[1]
    if not url.startswith('http'):  
        url = 'http://' + url
    parsed_url = urlparse.urlparse(url)
    host = parsed_url.hostname

    if check_http2(host):       #Call the function to check if the server supports HTTP/2, set http2_supported to True if it supports HTTP/2 protocol
        http2_supported = True


    send_request(sys.argv[1])   #Call the function to send requests to the server and print results
