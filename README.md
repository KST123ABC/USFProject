# **Average Joe Forensics Tool**

## **Team Members**

* ### Laura Weintraub
  #### RIT Computer Security Class of 2018
  #### lhw255@rit.edu

* ### Alex Lunderman
  #### RIT Computer Security Class of 2018
  #### aml5666@rit.edu

* ### Ryan Sidebottom
  #### RIT Computer Security Class of 2018
  #### rs4983@rit.edu

* ### Kyle Suero
  #### RIT Computer Security Class of 2018
  #### ks4829@g.rit.edu


## ** Requirements **
  * [OSQuery](https://osquery.io/downloads/official/2.11.2)
  * [Python3.6](https://www.python.org/downloads/)

## **What A.J.F.T. Does....**
The average, non-forensically trained user might not know how to analyze computer system logs and find suspicious activity. The goal of our tool is to do the hard work for these users. This is done by collecting the data, analyzing it, and producing human-readable output suggesting suspicious activity when suspected. Meaning you no longer have to be a pro to detect suspicious activity on your computer!

## **Implementation Details**
A.J.F.T. will function as a standalone python script that utilizes OSQueries tables. OSQueryi is an interactive tool to use SQL queries in order to access the information in these tables. Our script pulls information from these tables and then outputs the information into a readable format.

## **Getting Started**
1. Install OSQuery on local machine.
```
$ brew update
$ brew install OSQuery
```
2. Clone or download repo to machine.
```
$ git install https://github.com/KST123ABC/USFProject.git
```
3. Run Script.
```
$ python3 osqueryproject.py
```

## **License**
We will be using the MIT License for our Network Analysis Tool. We are not concerned with others using our code and we believe the more contributions made the more efficient the tool will be. To view the MIT License please see LICENSE file.
