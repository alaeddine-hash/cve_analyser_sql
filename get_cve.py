import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime

# Database connection parameters
DB_NAME = 'test'
DB_USER = 'postgres'
DB_PASSWORD = 'admin'
DB_HOST = '127.0.0.1'

def get_table_name(conn):
    """
    Attempt to find the table name for the CveDetail model.
    Assumes the table name ends with 'cvedetail'.
    """
    try:
        cur = conn.cursor()
        query = """
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema='public';
        """
        cur.execute(query)
        tables = [row[0] for row in cur.fetchall()]
        # Look for table names that end with 'cvedetail'
        possible_tables = [table for table in tables if table.lower().endswith('cvedetail')]
        if not possible_tables:
            print("No table matching 'cvedetail' found in the database.")
            print("Available tables:")
            for table in tables:
                print(table)
            return None
        elif len(possible_tables) == 1:
            return possible_tables[0]
        else:
            print("Multiple tables matching 'cvedetail' found:")
            for idx, table in enumerate(possible_tables):
                print(f"{idx + 1}. {table}")
            choice = int(input("Select the table number to use: ")) - 1
            return possible_tables[choice]
    except Exception as e:
        print(f"Error finding table name: {e}")
        return None

def filter_cves_by_year(cve_entries, published_year=None, modified_year=None):
    """
    Filters CVEs based on the year of 'published' and 'last_modified' dates.
    :param cve_entries: List of CVE entries (dictionaries)
    :param published_year: Year to filter 'published' date (int or list of ints)
    :param modified_year: Year to filter 'last_modified' date (int or list of ints)
    :return: Filtered list of CVE entries
    """
    filtered_cves = []

    for cve in cve_entries:
        pub_year = cve['published'].year
        mod_year = cve['last_modified'].year

        pub_match = True
        mod_match = True

        if published_year is not None:
            if isinstance(published_year, list):
                pub_match = pub_year in published_year
            else:
                pub_match = pub_year == published_year

        if modified_year is not None:
            if isinstance(modified_year, list):
                mod_match = mod_year in modified_year
            else:
                mod_match = mod_year == modified_year

        if pub_match and mod_match:
            filtered_cves.append(cve)

    return filtered_cves

def get_filtered_cves(published_year=None, modified_year=None, max_cves=None):
    """
    Retrieves a list of CVEs filtered by published and modified year, and limits the number of CVEs.
    :param published_year: Year to filter 'published' date (int or list of ints)
    :param modified_year: Year to filter 'last_modified' date (int or list of ints)
    :param max_cves: Maximum number of CVEs to retrieve (int)
    :return: List of CVE entries (dictionaries)
    """
    try:
        # Establish connection to the PostgreSQL database
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST
        )
        # Determine the table name
        table_name = get_table_name(conn)
        if not table_name:
            print("Cannot proceed without a valid table name.")
            return []

        # Create a cursor with RealDictCursor to get results as dictionaries
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # SQL query to retrieve unanalyzed CVE entries
        query = f"SELECT * FROM {table_name} WHERE analyzed = FALSE;"
        cur.execute(query)
        cve_entries = cur.fetchall()

        if not cve_entries:
            print("No unanalyzed CVE entries found.")
            return []

        # Filter CVEs based on the year of 'published' and 'last_modified' dates
        filtered_cves = filter_cves_by_year(
            cve_entries,
            published_year=published_year,
            modified_year=modified_year
        )

        if not filtered_cves:
            print(f"No CVE entries found for published year {published_year} and modified year {modified_year}.")
            return []

        # Limit the number of CVEs to retrieve
        if max_cves is not None:
            filtered_cves = filtered_cves[:max_cves]

        return filtered_cves

    except Exception as e:
        print(f"An error occurred: {e}")
        return []
    finally:
        # Close cursor and connection
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

# Remove or comment out the main function and any processing
# The script now provides the get_filtered_cves function for importing and use elsewhere


def get_cve_by_id(cve_id):
    """
    Retrieves a CVE entry based on the CVE ID.
    :param cve_id: The CVE ID to search for (string)
    :return: CVE entry as a dictionary or None if not found
    """
    try:
        # Establish connection to the PostgreSQL database
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST
        )
        # Determine the table name
        table_name = get_table_name(conn)
        if not table_name:
            print("Cannot proceed without a valid table name.")
            return None

        # Create a cursor with RealDictCursor to get results as dictionaries
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # SQL query to retrieve the CVE entry by ID
        query = f"SELECT * FROM {table_name} WHERE cve_id = %s;"
        cur.execute(query, (cve_id,))
        cve_entry = cur.fetchone()

        if not cve_entry:
            print(f"No CVE entry found for CVE ID {cve_id}.")
            return None

        return cve_entry

    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    finally:
        # Close cursor and connection
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()


