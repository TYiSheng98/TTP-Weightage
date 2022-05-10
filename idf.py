import os
import pandas as pd
import json
import numpy as np


prj_root = os.getcwd()
dataset_folderpath= os.path.join(prj_root,'mitre_nav_reports')
ttp_list_corpus=[]

# extract all mitre ttps in each mitre report
for root, dirs, files in os.walk(dataset_folderpath):
    for filename in files:
        abs_filepath = os.path.join(root,filename)
        # print(abs_filepath)
        with open(abs_filepath,'r') as f:
            data = data = json.load(f)

        df = pd.DataFrame(data['techniques'])
        # df = df[df['score'].notna()]
        df = df.loc[df['score'].isin([1.0])]
        ttp_list= df['techniqueID'].tolist()

        ttp_list_corpus.append(' '.join(ttp_list))

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
#instantiate CountVectorizer() 
cv=CountVectorizer(analyzer=lambda d: d.split(' ')) 
word_count_vector=cv.fit_transform(ttp_list_corpus)
#freq_count of all ttps
freq_count_dict = dict(zip(cv.get_feature_names(),word_count_vector.toarray().sum(axis=0)))
        
tfIdfVectorizer=TfidfVectorizer(use_idf=True,analyzer=lambda d: d.split(' '))
tfIdf = tfIdfVectorizer.fit_transform(ttp_list_corpus)
terms = tfIdfVectorizer.get_feature_names()

# https://github.com/annts/tf-id_demystified/blob/master/tf_idf_demo.ipynb
# create a dataframe from a word matrix
def dtm2df(wm, feat_names):
    
    # create an index for each row
    doc_names = ['Doc{:d}'.format(idx) for idx, _ in enumerate(wm)]
    df = pd.DataFrame(data=wm.toarray(), index=doc_names,
                      columns=feat_names)
    return(df)

def idf2df(wm, feat_names):
    # create an index for each row
    doc_names = ['Doc{:d}'.format(idx) for idx, _ in enumerate(wm)]
    df = pd.DataFrame(data=wm, index=[0],
                      columns=feat_names)
    return(df)

df_idf = idf2df(tfIdfVectorizer.idf_[:,np.newaxis].T ,terms)
df_idf= df_idf.sort_values(by =0, axis=1)
df_idf =df_idf.reset_index(drop=True)

# Using The min-max feature scaling
# copy the data
df_min_max_scaled = df_idf.copy().T
dataf=round(((df_min_max_scaled-df_min_max_scaled.min())/(df_min_max_scaled.max()-df_min_max_scaled.min()))*2,2)
dataf.index.name="TTP"
dataf['count'] = pd.Series(freq_count_dict)
dataf.reset_index(inplace=True)
dataf = dataf.rename(columns = {'index':'TTP'})

dataf.columns=['TTP','weight','count']
dataf.to_json('idf.json',orient='table',index=False)