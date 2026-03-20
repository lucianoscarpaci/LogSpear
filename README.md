# LogSpear
**IoT Botnet Detection & Forensic Analysis Tool**

A forensic tool designed for SOC Analysts to identify suspicious IoT devices involved in botnets through intelligent log analysis.

<img width="333" height="222" alt="medium" src="https://github.com/user-attachments/assets/27508843-6e6a-4ab4-9a64-fb0c0062e09b" />

305 Hackathon Miami March. 2026

Track #1 - Hackathon Competition - General Build
Track #2 - Business Venture Arena Competition
Opt-in Challenge #1
Opt-in Challenge #2
Opt-in Challenge #3

## Inspiration

This forensic tool was designed for SOC Analysts who want to find suspicious IoT devices that have been used in Botnets through their log scans. The faster the SOC can find the infected IoT devices such as CCTV's and EV charging stations on the network, they can prevent future devices from becoming infected.

## What it does

An LLM-powered incident summarizer. Users upload their log files to the chatbot interface to find the suspicious IP, Machine Information, Country of where the botnet is from, and a visualization in a graph of the botnet-like devices connected to it.

## How we built it

We built it using an AI Agent with Chainlit, OpenAI API, and LangChain.

## Key Features

- **IoT Device Detection**: Identifies suspicious IoT devices (CCTV cameras, EV charging stations, etc.) used in botnets
- **Comprehensive Analysis**: Extracts suspicious IP addresses, machine information, and country of origin
- **Visual Intelligence**: Graph visualization showing botnet-like devices and their connections
- **Chatbot Interface**: User-friendly Chainlit interface for uploading and analyzing log files
- **Fast Threat Detection**: Helps SOCs neutralize threats before additional devices become infected

## Challenges we ran into

The main challenge was setting up Chainlit web interface with langchain and coming up with the correct log files to analyze.

## Accomplishments that we're proud of

I am proud of helping Cybersecurity Analysts find these networks before they form and neutralize the threat before future devices get infected.

## What we learned

I learned how to use chainlit and langchain to help cybersecurity SOCs.

## Tech Stack

- **LLM Framework**: LangChain
- **Interface**: Chainlit
- **Language**: Python
- **Data Parsing**: JSON parsing with Python
- **Visualization**: Plotly for network graph visualization

## What's next for LogSpear

Integrating local, proprietary models, so that the data never leaves the network.

## Getting Started

Start the Python venv in your shell and install the packages from the requirements.txt file with pip.
```source venv/bin/activate && pip install -r requirements.txt```
Run the application with chainlit:
```chainlit run app/LogSpear/app.py```


## Demo video
![YouTube](https://youtu.be/0835dWM2oSI)
## Screenshots

![Screenshot 1](screenshots/Screen%20Shot%202026-03-20%20at%205.37.36%20PM.png)
![Screenshot 2](screenshots/Screen%20Shot%202026-03-20%20at%205.38.39%20PM.png)
![Screenshot 3](screenshots/Screen%20Shot%202026-03-20%20at%205.45.54%20PM.png)

## License
MIT License
See [LICENSE](LICENSE) file for details.
