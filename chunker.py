import os
import boto3
import botocore
import tempfile
import ffmpeg

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

def chunker(data):
    print("IN CHUNKER")
    metadata = {
        'title': data['title'],
        'desc': data['desc'],
        'id': data['id'],
        'user': data['user'],
        'time': data['time']
    }
    print(metadata)
    temp_dir = tempfile.mkdtemp()
    temp_video = os.path.join(temp_dir, 'temp-video.mp4')
    try:
        s3.download_file(bucket, data['key'], temp_video)
        hls_output = os.path.join(temp_dir, 'hls-chunks')
        os.makedirs(hls_output, exist_ok=True)
        try:
            ffmpeg.input(temp_video).output(
                os.path.join(hls_output, data['title']+'.m3u8'),
                format='hls',
                hls_time=10,
                hls_segment_type='mpegts',
                hls_list_size=0,
                hls_segment_filename=temp_dir+'/hls-chunks/'+data['title']+'_%d.ts'
            ).run()
        except Exception as e:
            print("error: ", e)
        try:
            for root, dirs, files in os.walk(hls_output):
                for file in files:
                    local_path = os.path.join(root, file)
                    key = os.path.join("videos/"+data['user']+"/", file)
                    s3.upload_file(local_path, bucket, key, ExtraArgs={'ACL': 'public-read', 'ContentType':'video/mp4', 'Metadata': metadata})
                    response = s3.list_objects_v2(Bucket=bucket, Prefix="videos/"+data['user']+'/')
        except Exception as e:
            print("Error: ", e)
        for obj in response.get('Contents', []):
            obj_key = s3.head_object(Bucket=bucket, Key=obj['Key'])['Metadata']
            if obj_key['title'] == data['title'] and obj_key['id'] == data['id']:
                s3.delete_object(Bucket=bucket, Key=obj['Key'])
                break
        print("success")
    except Exception as e:
        print("error: ", e)
        return e