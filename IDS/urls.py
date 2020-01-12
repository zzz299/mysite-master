from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'index/$', views.index),
    url(r'sniff/$', views.mysniff),
    url(r'upload/$',views.upload),
    url(r'show/$', views.show),
    url(r'analysis/$', views.analysis1),
    url(r'attacklogs/$', views.attacklogs),
    url(r'sniff/$',views.mysniff),
    url(r'getpcap_num/$', views.getpcap_num),
    url(r'get_attack_nums/$', views.get_attack_num),

]