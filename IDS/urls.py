from django.urls import path
from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'index/$', views.index),
    url(r'sniff/$', views.mysniff),
    url(r'upload/$',views.upload),
    # url(r'catch/$',views.catch),
    url(r'show/$', views.show),
    url(r'analysis/$', views.analysis1),
    url(r'attacklogs/$', views.attacklogs),
    url(r'sniff/$',views.mysniff),
    url(r'test_ajax/$',views.test_ajax),
    url(r'test_ajax_add/$',views.test_ajax_add),
    url(r'testecharts/$', views.testecharts),
    url(r'get_sqlinjection_nums/$', views.get_sqlinjection_num),

]