# Phishing Domain Detection

## Overview
Phishing is a form of fraud where attackers pose as trusted entities to obtain sensitive details like login credentials or account information through emails or other communication channels. It is favored by attackers due to the simplicity of deceiving individuals into clicking seemingly legitimate but harmful links, compared to bypassing advanced security systems. The primary objective is to determine whether domains are genuine or malicious. For this we have developed a web application using flask and Machine Learning techniques to detect if a site is a legitimate or a phishing site.

## Project Structure
The project is organized as follows:

```bash
Phishing Domain Detection
│
├── app
│   ├── templates
│   │   └── index.html
│   ├── __init__.py
│   └── app.py
│
├── data
│   ├── dataset_full.csv
│   └── dataset_small.csv
│
├── docs
│   └── Phishing Domain Detection.pdf
│
├── model
│   ├── Feature_Names.pkl
│   └── Phishing_Model.pkl
│
├── notebook
│   └── phishing_domain_detection.ipynb
│
├── scripts
│   ├── __init__.py
│   └── link_extractor.py
│
├── __init__.py
├── main.py
├── readme.md
└── requirements.txt
```



### Explanation of Components:
1. **app**:
   - `templates/index.html`: The HTML file for the user interface, allowing users to interact with the application visually.
   - `__init__.py`: Initializes the app module and contains basic setup configurations.
   - `app.py`: Implements the main functionality of the application, handling requests and connecting the front-end to the back-end.

2. **data**:
   - `dataset_full.csv`: The complete dataset used for training and testing the machine learning model.
   - `dataset_small.csv`: A subset of the dataset for quick tests or preliminary analysis.

3. **docs**:
   - `Phishing Domain Detection.pdf`: Documentation explaining the project, including its objectives, methodologies, and outcomes.

4. **model**:
   - `Feature_Names.pkl`: Serialized file containing the features used by the machine learning model.
   - `Phishing_Model.pkl`: The trained phishing detection model saved for deployment or reuse.

5. **notebook**:
   - `phishing_domain_detection.ipynb`: Jupyter Notebook used for data analysis, feature engineering, and model training.

6. **scripts**:
   - `__init__.py`: Initializes the scripts module, making it a package.
   - `link_extractor.py`: Script for extracting and analyzing links for phishing detection features.

7. **__init__.py**:
   - Marker file for Python packages.

8. **main.py**:
   - The main entry point coordinating app, scripts, and model components.

9. **readme.md**:
   - The README file providing an overview, setup instructions, and project details.

10. **requirements.txt**:
    - Lists dependencies and libraries required to run the project.

## Technologies Used
```
●	Programming Language: Python
●	Machine Learning Libraries: Scikit-learn
●	Data Visualization: Matplotlib, Seaborn
●	Data Preprocessing: Numpy, Pandas, Joblib(To Load Data)
●	Networking Libraries: ipwhois, urllib3, dnspython, whois, requests.
●	Framework: Flask.
```
## How to Run the Project
1. Clone the repository:
  ``` git clone https://github.com/aksanthoshprofessional/PhishingDomainDetection.git ```

2. Install the required Python packages:
    pip install -r requirements.txt

3. Start the server:
    python main.py
