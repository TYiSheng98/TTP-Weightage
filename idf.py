import os
import pandas as pd
import json
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfTransformer


# src: https://github.com/annts/tf-id_demystified/blob/master/tf_idf_demo.ipynb
# create a dataframe from a word matrix
def idf2df(wm, feat_names):
    # create an index for each row
    doc_names = ['Doc{:d}'.format(idx) for idx, _ in enumerate(wm)]
    df = pd.DataFrame(data=wm, index=[0],
                      columns=feat_names)
    return(df)


def main():
    
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
            # extract ttp that only has a score of 1.0
            df = df.loc[df['score'].isin([1.0])]
            # extract all ttps to a list in each report
            ttp_list= df['techniqueID'].tolist()
            # append all ttps to a string for each report
            ttp_list_corpus.append(' '.join(ttp_list))


    # src: https://github.com/kavgan/nlp-in-practice/blob/master/tf-idf/Keyword%20Extraction%20with%20TF-IDF%20and%20SKlearn.ipynb
    #instantiate CountVectorizer() 
    cv=CountVectorizer(analyzer=lambda d: d.split(' ')) 
    word_count_vector=cv.fit_transform(ttp_list_corpus)
    terms = cv.get_feature_names()

    #freq count of all ttps that exists in the mitre reports
    freq_count_dict = dict(zip(terms,word_count_vector.toarray().sum(axis=0)))

    tfidf_transformer=TfidfTransformer(smooth_idf=True,use_idf=True)
    tfidf_transformer.fit(word_count_vector)

    # idf_ attribute can be used to extract IDF values 
    #transpose the 1D IDF array to convert to a dataframe to make it easy to visualise
    df_idf = idf2df(tfidf_transformer.idf_[:,np.newaxis].T ,terms)
    df_idf= df_idf.sort_values(by =0, axis=1)

    # Using The min-max feature scaling to normalize the weightage
    df_min_max_scaled = df_idf.copy().T
    #Normalize the weightage from the scsale of 0 to 2
    dataf=round(((df_min_max_scaled-df_min_max_scaled.min())/(df_min_max_scaled.max()-df_min_max_scaled.min()))*2,2)
    dataf.index.name="TTP"
    dataf.columns=['weight']

    # output the dataframe to json format
    dataf.to_json('idf_weightage.json',index=True)

if __name__ == "__main__":
    main()