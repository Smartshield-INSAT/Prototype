import pandas as pd
import numpy as np

def features(df):
        epsilon = 1e-10  # Small constant to avoid division by zero

        df["Speed of Operations to Speed of Data Bytes"] = np.log1p(df["sbytes"] / (df["dbytes"] + epsilon))
        df["Time for a Single Process"] = np.log1p(df["dur"] / (df["spkts"] + epsilon))
        df["Ratio of Data Flow"] = np.log1p(df["dbytes"] / (df["sbytes"] + epsilon))
        df["Ratio of Packet Flow"] = np.log1p(df["dpkts"] / (df["spkts"] + epsilon))
        df["Total Page Errors"] = np.log1p(df["dur"] * df["sloss"])
        df["Network Usage"] = np.log1p(df["sbytes"] + df["dbytes"])
        return df.head()
def process_file(filename):
        df=pd.read_csv(filename)
        print(features(df))
        with open(filename, "wb") as f:
                df.to_csv(path_or_buf=f)
if __name__ == "__main__":
        process_file("10_samples.csv")
