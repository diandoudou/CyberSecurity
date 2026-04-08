import csv

# path to the input txt file
input_file = 'csv.txt'
# Output csv file path
output_file = 'output.csv'

with open(input_file, 'r', encoding='utf-8') as infile, open(output_file, 'w', newline='', encoding='utf-8') as outfile:
    # create csv write object
    writer = csv.writer(outfile)

    # Skip the comment lines at the beginning of the txt file
    for line in infile:
        if not line.startswith('#'):
            # Split the lines by commas
            row = line.strip().split(',')
            # Write to csv file
            writer.writerow(row)