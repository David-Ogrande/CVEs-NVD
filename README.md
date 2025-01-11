# Installation

To use this code to collect CVE information from the NVD site (https://www.nist.gov/), it is recommended to create a virtual environment.

```python
python -m venv env
```

Then just install the requirements for the project.

```python
pip install -r requirements.txt
```

Enter the cves you want to obtain information on in the cves.txt file.

Example:

```
CVE-2021-44228
CVE-2017-0144
CVE-2020-1472
CVE-2014-6271
CVE-2018-8174
CVE-2019-0708
```

At the end, run the main.py script and check the result in the file result.csv.

```python
python main.py
```
