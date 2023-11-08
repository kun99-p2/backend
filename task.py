import boto3
import botocore
from moviepy.editor import VideoFileClip
import tempfile
import os
import imageio

access_key = 'DO00JQGULATEWKWZYCHA'
secret = '5rpGncSUAkl0BCo0E63FBy5FR3EO/daTuwxZPvOcp+8'
endpoint = 'https://sgp1.digitaloceanspaces.com'
bucket = 'ss-p2'
session = boto3.session.Session()
s3 = session.client('s3',
                        config=botocore.config.Config(s3={'addressing_style': 'virtual'}),
                        region_name='sgp1',
                        endpoint_url='https://sgp1.digitaloceanspaces.com',
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret)

def extract_thumbnail(data):
    temp_video = None
    temp_tb = None
    try:
        metadata = {
            'title': data['title'],
            'desc': data['desc'],
            'id': data['id'],
            'user': data['user'],
            'time': data['time']
        }
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_video:
            try:
                s3.download_file(bucket, data['key'], temp_video.name)
            except Exception as e:
                return e
            clip = VideoFileClip(temp_video.name)
            thumbnail = clip.get_frame(1)
            clip.close()
            with tempfile.NamedTemporaryFile(delete=False, mode='wb', suffix='.jpg') as temp_tb:
                imageio.imwrite(temp_tb.name, thumbnail)
                try:
                    s3.upload_file(temp_tb.name, bucket, "thumbnail/"+data['user']+"/"+data['title']+".jpg", ExtraArgs={'ACL': 'public-read', 'ContentType':'image/jpg', 'Metadata': metadata})
                except Exception as e:
                    return e
    except Exception as e:
        return e
    finally:
        if temp_video:
            temp_video.close()
            os.remove(temp_video.name)
        if temp_tb:
            temp_tb.close()
            os.remove(temp_tb.name)
    
    