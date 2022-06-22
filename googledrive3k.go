package googledrive3k

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

var DriveScope = []string{drive.DriveScope}
var DriveScopeReadOnly = []string{drive.DriveReadonlyScope}

func BuildNewGoogleDrive3kOAuth2(subject string, scopes []string, clientSecret, authorizationToken []byte, ctx context.Context) *API {
	config, err := google.ConfigFromJSON(clientSecret, scopes...)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}
	token := &oauth2.Token{}
	err = json.Unmarshal(authorizationToken, token)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}
	client := config.Client(context.Background(), token)
	return BuildNewGoogleDrive3k(client, subject, ctx)
}

func BuildNewGoogleDrive3kImpersonation(subject string, scopes []string, serviceAccountKey []byte, ctx context.Context) *API {
	jwt, err := google.JWTConfigFromJSON(serviceAccountKey, scopes...)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}
	jwt.Subject = subject
	return BuildNewGoogleDrive3k(jwt.Client(ctx), subject, ctx)
}

func BuildNewGoogleDrive3k(client *http.Client, subject string, ctx context.Context) *API {
	newGoogleDrive3k := &API{}
	service, err := drive.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Fatalf(err.Error())
	}
	newGoogleDrive3k.Service = service
	newGoogleDrive3k.Subject = subject
	newGoogleDrive3k.Jobs = &sync.WaitGroup{}
	return newGoogleDrive3k
}

type API struct {
	Service *drive.Service
	Subject string
	Jobs    *sync.WaitGroup
}

type FileTransfer struct {
	NewOwner string
	DriveAPI *API
	Files    []string
}

type DownloadedFile struct {
	Drivefile *drive.File
	Data      []byte
}

func (receiver *API) GetAbout() *drive.About {
	log.Printf("Getting Drive.About of [%s]\n", receiver.Subject)
	response, err := receiver.Service.About.Get().Fields("*").Do()
	if err != nil {
		log.Println(err.Error())
		return nil
	}
	return response
}

func (receiver *API) GetFileById(fileId string) (*drive.File, error) {
	file, err := receiver.Service.Files.Get(fileId).Fields("*").SupportsTeamDrives(true).SupportsAllDrives(true).Do()
	if err != nil {
		if strings.Contains(err.Error(), "Drivefile not found:") {
			log.Println(err.Error())
			return nil, err
		}
		log.Println(err.Error())
		log.Println("Error encountered Sleeping for 2 seconds...")
		time.Sleep(time.Second * 2)
		return receiver.GetFileById(fileId)
	}
	log.Printf("Returned [%s] -> \"%s\"\n", fileId, file.Name)
	return file, err
}

func (receiver *API) QueryFiles(q string) []*drive.File {
	var allFiles []*drive.File
	request := receiver.Service.Files.List().Q(q).Fields("*").PageSize(1000)

	for {
		response, err := request.Do()
		for {
			if err != nil {
				if strings.Contains(err.Error(), "500") || strings.Contains(err.Error(), "Error 40") {
					log.Println(err.Error())
					log.Printf("Backing off for 3 seconds, will try (%s) again...\n", q)
					time.Sleep(time.Second * 3)
					response, err = request.Do()
				}
			} else {
				break
			}
		}
		allFiles = append(allFiles, response.Files...)
		request.PageToken(response.NextPageToken)
		log.Printf("User: %s, Query: %s, Total returned: %d \n", receiver.Subject, q, len(allFiles))
		if response.NextPageToken == "" {
			break
		}
	}
	return allFiles
}

func (receiver *API) MoveFile(fileId, parentFolderId string) (*drive.File, error) {
	updatedDriveFile, err := receiver.Service.Files.Update(
		fileId,
		&drive.File{}).
		SupportsTeamDrives(true).
		AddParents(parentFolderId).Do()
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	log.Printf("Drive file [%s] moved to --> [%s]\n", fileId, parentFolderId)
	return updatedDriveFile, err
}

func (receiver *API) CopyFile(fileId, parentFolderId, fileName string) *drive.File {
	msg := "Copy of [" + fileId + "]"
	response, err := receiver.Service.Files.Copy(fileId, &drive.File{Parents: []string{parentFolderId}}).Do()
	if err != nil {
		log.Println(msg + " FAILED...")
		if strings.Contains(err.Error(), "This file cannot be copied by the user.") {
			log.Printf("%s\n\tDrivefile Id: %s\n\tDrivefile Name: %s\n\tDrivefile Location: %s\n\n", err.Error(), fileId, fileName, parentFolderId)
			return nil
		}
		log.Printf("%s\nSleeping for 3 seconds...", err.Error())
		time.Sleep(time.Second * 2)
		return receiver.CopyFile(fileId, parentFolderId, fileName)

	}
	log.Println(msg+response.Name, "SUCCESS...")
	return response
}

func GetTransferCall(newOwner, fileId string, service *drive.Service) *drive.PermissionsCreateCall {
	newPermission := &drive.Permission{}
	newPermission.EmailAddress = newOwner
	newPermission.Role = "owner"
	newPermission.Type = "user"
	return service.Permissions.Create(fileId, newPermission).TransferOwnership(true).SupportsAllDrives(true)
}

func (receiver *API) ChangeFileOwner(newOwner, fileId string, doIt bool) *drive.Permission {
	changeOwnerRequest := GetTransferCall(newOwner, fileId, receiver.Service)
	msg := "Drivefile [" + fileId + "] old owner [" + receiver.Subject + "] -> new owner [" + newOwner + "] "
	if doIt {
		response, err := changeOwnerRequest.Do()
		if err != nil {
			if strings.Contains(err.Error(), "Sorry, the items were successfully shared but emails could not be sent to") {
				log.Println(msg + "SUCCESS - Ownership change email not sent")
				return response
			}
			if strings.Contains(err.Error(), "some error code") {
				log.Println(err.Error())
				log.Println(msg + "FAILED - Retrying")
				time.Sleep(3 * time.Second)
				return receiver.ChangeFileOwner(newOwner, fileId, doIt)
			} else {
				log.Println(msg + "FAILED\n\t" + err.Error())
				return nil
			}
		}
		log.Println(msg + "SUCCESS")
		return response
	} else {
		log.Println(msg + " DID NOT EXECUTE")
		return nil
	}
}

func (receiver *API) ChangeFileOwnerWorker(newOwner, fileId string, doIt bool, wg *sync.WaitGroup) {
	receiver.ChangeFileOwner(newOwner, fileId, doIt)
	wg.Done()
}

func (receiver *API) UploadFile(filename, parentFolderId string, data []byte) (*drive.File, error) {

	progressUpdater := googleapi.ProgressUpdater(func(now, size int64) {
		log.Printf("Current file: %s [%d of %d]\n", filename, ByteCount(now), ByteCount(int64(len(data))))
	})

	result, err := receiver.Service.Files.
		Create(&drive.File{Name: filename, Parents: []string{parentFolderId}}).
		Media(bytes.NewReader(data)).
		ProgressUpdater(progressUpdater).
		Do()

	if err != nil {
		log.Println(err.Error())
		return result, err
	}

	return result, err

}

func (receiver *API) CopyFolder(sourceFolderId, newSourceFolderName, parentFolderId string) {

	/*Get source folder*/
	sourceFolder, _ := receiver.GetFileById(sourceFolderId)
	sourceFolder.Name = newSourceFolderName
	msg := "Copy of [" + sourceFolder.Name + "]"

	/*Create a copy source folder*/
	sourceCopy, _ := receiver.CreateFolder(sourceFolder.Name, parentFolderId, nil)

	/*FileIdList that will be copied*/
	var filesToCopy [][]string
	var copyMap = make(map[string]string)

	/*Get all kids from SourceFolder*/
	for _, currentObject := range receiver.QueryFiles("'" + sourceFolder.Id + "' in parents") {
		if strings.Contains(currentObject.MimeType, "folder") {
			/*If file is a folder, copy that folder and play it in the current folder*/
			receiver.CopyFolder(currentObject.Id, currentObject.Name, sourceCopy.Id)
			log.Println(msg + " SUCCESS...")
			continue
		} else if strings.Contains(currentObject.MimeType, "shortcut") { // Added: 3/18/2021
			receiver.Service.Files.Get(currentObject.Id).Fields()
		}
		//CopyFile(currentObject.Id, parentFolderId)
		copyMap[currentObject.Id] = parentFolderId
		filesToCopy = append(filesToCopy, []string{currentObject.Id, sourceCopy.Id, currentObject.Name})
	}

	totalItems := len(filesToCopy) //Total Work Items
	maxGoRoutines := 10            //Max GoRoutines
	counter := 0                   //Counter

	for len(filesToCopy) != 0 {
		log.Println("Working [" + fmt.Sprint(counter) + "] of [" + fmt.Sprint(totalItems) + "]")
		if len(filesToCopy) < maxGoRoutines {
			currentItems := filesToCopy[:]
			waitgroup := sync.WaitGroup{}
			waitgroup.Add(len(currentItems))
			for _, item := range currentItems {
				go receiver.CopyFileWorker(item, &waitgroup)
				counter++
			}
			waitgroup.Wait()
			break
		} else {
			currentItems := filesToCopy[:maxGoRoutines]
			waitgroup := sync.WaitGroup{}
			waitgroup.Add(len(currentItems))
			for _, item := range currentItems {
				go receiver.CopyFileWorker(item, &waitgroup)
				counter++
			}
			waitgroup.Wait()
			filesToCopy = append(filesToCopy[:0], filesToCopy[maxGoRoutines:]...)
		}
	}
}

func (receiver *API) CreateFolder(folderName, parentFolderId string, permissions []*drive.Permission) (*drive.File, error) {
	file := &drive.File{}
	file.MimeType = "application/vnd.google-apps.folder"
	file.Name = folderName
	file.Parents = append(file.Parents, parentFolderId)

	driveFileCreateResponse, err := receiver.Service.Files.Create(file).Do()
	if err != nil {
		if strings.Contains(err.Error(), "limit") {
			log.Println(err.Error())
			log.Println("Api limit reached. Sleeping for 2 seconds...")
			time.Sleep(time.Second * 2)
			return driveFileCreateResponse, err
		}
	}

	if permissions != nil {
		for _, permission := range permissions {
			permissionResponse, err := receiver.Service.Permissions.Create(driveFileCreateResponse.Id, permission).SendNotificationEmail(false).Do()
			if err != nil {
				log.Println(err.Error())
				return nil, err
			}
			log.Printf("Shared \"%s\" [%s] to <%s> as a {%s}", driveFileCreateResponse.Name, driveFileCreateResponse.Id, permission.EmailAddress, permissionResponse.Role)

		}
	}

	log.Printf("Created folder %s[%s]", driveFileCreateResponse.Name, driveFileCreateResponse.Id)
	return driveFileCreateResponse, err
}

func (receiver *API) GetNestedFiles(targetFolderId string) []*drive.File {
	targetFolder, _ := receiver.GetFileById(targetFolderId)
	log.Println("Pulling Children from folder [" + targetFolder.Id + "] - " + targetFolder.Name)
	files := receiver.QueryFiles("'" + targetFolder.Id + "' in parents")
	if files == nil {
		log.Println("No files found in [" + targetFolder.Id + "]")
		return nil
	}
	var fileList []*drive.File
	for _, file := range files {
		log.Printf("CurrentFile: %s, {%s} - [%s]", file.Name, file.MimeType, file.Id)
		//Append data and keep going if folder
		if file.MimeType == "application/vnd.google-apps.folder" {
			fileList = append(fileList, receiver.GetNestedFiles(file.Id)...)
		}
		fileList = append(fileList, file)
	}

	return fileList
}

func (receiver *API) GetNestedFilesUsingRoutines(targetFolderId string) []*drive.File {
	var fileList []*drive.File
	q := fmt.Sprintf("'%s' in parents", targetFolderId)
	queryResponse := receiver.QueryFiles(q)
	if queryResponse == nil {
		return nil
	}
	for _, file := range queryResponse {
		log.Printf("Current Object: %s, [%s] - %s", file.Name, file.Id, file.MimeType)
		if file.MimeType == "application/vnd.google-apps.folder" {
			wg := &sync.WaitGroup{}
			wg.Add(1)
			go func(f *drive.File) {
				defer wg.Done()
				fileList = append(fileList, receiver.GetNestedFilesUsingRoutines(f.Id)...)
			}(file)
			wg.Wait()
		}
		fileList = append(fileList, file)
	}
	return fileList
}

func (receiver *API) GetFilePermissions(file *drive.File) string {
	var permissionEmails string

	for count, permission := range file.Permissions {
		if strings.Contains(permission.Role, "owner") {
			continue
		}
		p := permission.EmailAddress //+ "(" + currentPermission.Role + ")"
		permissionEmails += p
		fmt.Sprint(count)
		if count == len(file.Permissions)-2 {
			break
		}
		permissionEmails += ","

	}
	return permissionEmails
}

func (receiver *API) RemoveUserPermission(fileId string, permission *drive.Permission, execute bool) error {
	if execute == false {
		log.Printf("\t\tWould remove %s from %s *DID NOT EXECUTE*\n", permission.EmailAddress, fileId)
		return nil
	}
	log.Printf("\t\tRemoving %s from %s\n", permission.EmailAddress, fileId)
	err := receiver.Service.Permissions.Delete(fileId, permission.Id).Do()
	if err != nil {
		log.Println(err.Error())
		return err
	}
	return err
}

func (receiver *API) RemovePermissionByID(fileID, permissionID string, execute bool) error {
	if execute == false {
		log.Printf("\t\tWould remove [%s] from %s *DID NOT EXECUTE*\n", permissionID, fileID)
		return nil
	}

	err := receiver.Service.Permissions.Delete(fileID, permissionID).Do()
	if err != nil {
		log.Println(err.Error())
		return err
	}

	log.Printf("Removed [%s] from %s\n", permissionID, fileID)
	return nil
}

func (receiver *API) ShareFile(fileId, email, accountType, role string, notify, doIt bool) (*drive.Permission, error) {

	if doIt {
		response, err := receiver.Service.
			Permissions.
			Create(fileId, &drive.Permission{EmailAddress: email, Type: accountType, Role: strings.ToLower(role)}).
			Fields("*").
			SendNotificationEmail(notify).
			Do()

		if err != nil {
			log.Printf("Sharing: %s, to: %s as [%s, %s] FAILED", fileId, email, accountType, role)
			log.Fatalf(err.Error())
			return nil, err
		}
		log.Printf("Sharing: %s, to: %s as [%s, %s] SUCCESS", fileId, email, accountType, role)
		return response, err
	}

	log.Printf("Sharing: %s, to: %s as [%s, %s] DID NOT EXECUTE", fileId, email, accountType, role)
	return &drive.Permission{}, nil

}

func (receiver *API) PermissionShareHandler(calls []*drive.PermissionsCreateCall, doIt bool) {
	totalCalls := len(calls)
	maxExecutes := 1
	for {
		if len(calls) < maxExecutes {
			maxExecutes = len(calls)
		}

		wg := &sync.WaitGroup{}
		wg.Add(maxExecutes)

		for _, job := range calls[:maxExecutes] {
			go func(worker *drive.PermissionsCreateCall) {
				user := worker.Header().Get("user")
				url := worker.Header().Get("url")
				role := worker.Header().Get("role")
				defer wg.Done()
				if doIt == true {
					_, err := worker.Do()
					if err != nil {
						log.Println(err.Error())
						log.Printf("FAILED --> Share Drivefile[%s] to %s<%s>", url, user, role)
					}
					log.Printf("SUCCESS --> Share Drivefile[%s] to %s<%s>", url, user, role)
				} else {
					log.Printf("DID NOT EXECUTE --> Share Drivefile[%s] to %s<%s>", url, user, role)
				}
			}(job)
		}
		wg.Wait()
		calls = calls[maxExecutes:]
		if len(calls) == 0 {
			break
		}
	}
	log.Printf("Total Calls executed: %d\n", totalCalls)
}

func (receiver *API) CopyFileWorker(fileInformation []string, wg *sync.WaitGroup) {
	receiver.CopyFile(fileInformation[0], fileInformation[1], fileInformation[2])
	wg.Done()
}

func (receiver *API) RemoveUserPermissionWorker(fileID string, permission *drive.Permission, wg *sync.WaitGroup, execute bool) error {
	err := receiver.RemoveUserPermission(fileID, permission, execute)
	wg.Done()
	return err //Channels?
}

func (receiver *API) RemovePermissionByIDWorker(fileID, permissionId string, wg *sync.WaitGroup, execute bool) error {
	err := receiver.RemovePermissionByID(fileID, permissionId, execute)
	wg.Done()
	return err //Channels?
}

func (receiver *API) DownloadFileById(fileId string) (*DownloadedFile, error) {
	file, err := receiver.GetFileById(fileId)
	if err != nil {
		log.Println(err.Error())
		panic(err)
		return nil, err
	}
	return receiver.DownloadFile(file)
}

func (receiver *API) DownloadFile(file *drive.File) (*DownloadedFile, error) {
	log.Printf("Retrieving %s as a blob from Google Drive...\n", file.Id)
	var blob []byte
	var err error
	var response *http.Response

	if strings.Contains(file.MimeType, "shortcut") ||
		strings.Contains(file.MimeType, "folder") {
		log.Printf("Drivefile \"%s\" [%s] is a %s and will not be downloaded\n", file.Name, file.Id, file.MimeType)
		return &DownloadedFile{Drivefile: file, Data: blob}, err
	} else if strings.Contains(file.MimeType, "google") {
		osMimeType, ext := GetOSMimeType(file.MimeType)
		if osMimeType == "" {
			return &DownloadedFile{Drivefile: file, Data: blob}, err
		}
		file.FileExtension = ext
		file.OriginalFilename = file.Name + ext
		response, err = receiver.Service.Files.Export(file.Id, osMimeType).Download()
		log.Printf("Drivefile \"%s\" [%s] - Converted from %s to a %s\n", file.Name, file.Id, strings.Split(file.MimeType, "vnd.")[1], osMimeType)
	} else {
		log.Printf("Drivefile \"%s\" [%s] - saved as from %s\n", file.Name, file.Id, file.FullFileExtension)
		response, err = receiver.Service.Files.Get(file.Id).Download()
	}

	blob, err = ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf(err.Error())
	}

	if file.Size < 1 {
		file.Size = int64(len(blob))
	}

	log.Printf("Size: %s, Drivefile: \"%s\", ID:[%s], Type: %s\n", ByteCount(int64(len(blob))), file.Name, file.Id, file.MimeType)
	return &DownloadedFile{Drivefile: file, Data: blob}, err
}

func ByteCount(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

func GetOSMimeType(googleWorkspaceMimeType string) (string, string) {
	switch googleWorkspaceMimeType {
	case "application/vnd.google-apps.spreadsheet":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx"
	case "application/vnd.google-apps.document":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".docx"
	case "application/vnd.google-apps.presentation":
		return "application/vnd.openxmlformats-officedocument.presentationml.presentation", ".pptx"
	case "application/vnd.google-apps.script":
		return "text/javascript", ".js"
	case "application/vnd.google-apps.photo":
		return "image/png", ".png"
	case "application/vnd.google-apps.video":
		return "video/mp4", ".mp4"
	case "application/vnd.google-apps.drawing":
		return "image/png", ".png"
	case "application/vnd.google-apps.audio":
		return "audio/mpeg", ".mp3"
	case "application/vnd.google-apps.site":
		return "text/plain", ".txt"
	default:
		return "", ""
	}
}
