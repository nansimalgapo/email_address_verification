import re
import time
import json
import socket
import pandas as pd
from validate_email_address import validate_email

# List of disposable email domains
with open('disposable_email_domains.json', 'r') as file:
    disposable_domains = json.load(file)

domain_counts = {domain: 0 for domain in disposable_domains}


def validate_email_address(email_address):
    # Get Domain
    try:
        domain = email_address.split('@')[1].lower()
    except IndexError:
        return 'not an email address'

    # Step 1: Disposable email address detection
    if domain in disposable_domains:
        return 'disposable'

    # Step 2: Validate email address using Python library
    if not validate_email(email_address):
        return 'invalid email address'

    try:
        # Step 3: Perform a DNS lookup for the Mail Exchange (MX) records of the specified domain.
        mx_records = socket.getaddrinfo(domain, 25, socket.AF_INET, socket.SOCK_STREAM)
        if not mx_records:
            return 'invalid domain'
    except socket.gaierror:
        return 'invalid domain'

    return 'valid email address'


# Test email addresses
file = 'FRAUD MAY-JULY20.xlsx'
df = pd.read_excel(file, sheet_name='USER TABLE')[['Email']]
df = df.dropna(subset=['Email'])
email_list = df['Email'].to_list()
start = time.time()
# Check validity for each email address and append to the results list
print('Checking each email address ..')
results = []
is_suspicious_list = []  # List to store the is_suspicious column
unique_strings = set()

for email in email_list:
    if str(email) != 'nan':
        result = validate_email_address(email)
        results.append(result)

        # Check for suspicious email based on unique strings
        nopunc_email = re.sub('[!@#$%^&*()-=+.,]', '', email.lower())
        nonum_email = re.sub(r'[0-9]+', '', nopunc_email).strip()
        is_suspicious = nonum_email in unique_strings or result in ['disposable', 'invalid email address', 'invalid domain']
        is_suspicious_list.append(is_suspicious)

        if result == 'disposable':
            domain = email.split('@')[1].lower()
            if domain in domain_counts:
                domain_counts[domain] += 1

        unique_strings.add(nonum_email)

# Convert the dictionary to a DataFrame
investigation_df = pd.DataFrame(list(domain_counts.items()), columns=['Domain', 'Occurrence'])
# Filter out the domains with 0 occurrences
investigation_df = investigation_df[investigation_df['Occurrence'] > 0]
# Calculate and add the "Total" row to the DataFrame
total_row = pd.DataFrame([['Total', investigation_df['Occurrence'].sum()]], columns=['Domain', 'Occurrence'])
investigation_df = pd.concat([investigation_df, total_row])
investigation_df.to_csv('domain_name_investigation_0507.csv', index=False)
results_df = pd.DataFrame({
    'emails': email_list,
    'results': results
})
# Add the 'is_suspicious' column to the results_df DataFrame
results_df['is_suspicious'] = is_suspicious_list

# Write the results to a single CSV file containing both 'result' and 'is_suspicious' columns
results_df.to_csv('email_validation_results_0507.csv', index=False)

end = time.time()
print('Total processing time in minutes: ', round((end-start)/60, 2))
