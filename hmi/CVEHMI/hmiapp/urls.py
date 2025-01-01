from django.urls import path
from . import views
from .views import LoginView,LogoutView,TokenRefreshView,UserView,ShareProjectsView,AddProjectView,UserProjectsView,ScanXMLProjectView,ScanHistoryView,AllScanHistoryView,AbortScanView,ModifyProjectView,ProjectDeleteView,ProjectDetailView,ShareProjectView,ProjectModificationHistoryView,pdf_url_view, LogDownloadView, ReportDownloadView,save_filters,ScanLogDownloadView,ActiveScansSSEView,StartBackgroundScanView,CVESyncLogView
urlpatterns = [
   # path('api/login/', views.user_login, name='login'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/logout/', LogoutView.as_view(), name='logout'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/user/', UserView.as_view(), name='user'),
    path('api/add-project/',AddProjectView.as_view(),name='add_project'),
    path('api/user-projects/',UserProjectsView.as_view(),name='view-projects'),
    path('api/share-projects/',ShareProjectsView.as_view(),name='view-project'),
    path('sse/active-scans/', ActiveScansSSEView.as_view(), name='sse-active-scans'),
    path('api/start-background-scan/', StartBackgroundScanView.as_view(), name='start-scans'),
    path('api/project/<int:project_id>/', ProjectDetailView.as_view(), name='project-detail'),
    path('api/modify-project/<int:project_id>/', ModifyProjectView.as_view(), name='modify-project'),
    path('api/user-projects/<int:project_id>/delete/', ProjectDeleteView.as_view(), name='project_delete'),
    path('api/scan-project/<int:project_id>/',ScanXMLProjectView.as_view(), name='scan_project'),
    path('api/scan-history/<int:project_id>/', ScanHistoryView.as_view(), name='scan-history'),
    path('api/all-scan-history/<int:project_id>/', AllScanHistoryView.as_view(), name='all-scan-history'),
    path('api/abort-scan/',AbortScanView.as_view(),name='abort-scan'),
    path('api/share-project/',ShareProjectView.as_view(),name='share-project'),
    path('api/save-filters/', save_filters, name='save_filters'),
    path('api/pdf-url/', pdf_url_view, name='pdf_url'),
    path('api/report-download/<str:project_id>/<str:scan_id>/', ReportDownloadView.as_view(), name='report_download'),
    path('api/download-log/', LogDownloadView.as_view(), name='download_log'),
    path('api/project/<int:project_id>/history/',ProjectModificationHistoryView.as_view(),name='modify-history'),  
    path('api/scan-log-download/<str:project_id>/<str:scan_id>/', ScanLogDownloadView.as_view(), name='scan-log-download'),
    path('api/cve-sync-log/', CVESyncLogView.as_view(), name='cve-sync-log')
]



