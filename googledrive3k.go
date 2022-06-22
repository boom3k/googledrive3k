package googledrive3k

import (
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
	"os"
	"strings"
	"sync"
	"time"
)

var DriveScope = []string{drive.DriveScope}
var DriveScopeReadOnly = []string{drive.DriveReadonlyScope}

func BuildNewGoogleDrive3kOAuth2(subject string, scopes []string, clientSecret, authorizationToken []byte, ctx context.Context) *GoogleDrive3k {
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

func BuildNewGoogleDrive3kImpersonation(subject string, scopes []string, serviceAccountKey []byte, ctx context.Context) *GoogleDrive3k {
	jwt, err := google.JWTConfigFromJSON(serviceAccountKey, scopes...)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}
	jwt.Subject = subject
	return BuildNewGoogleDrive3k(jwt.Client(ctx), subject, ctx)
}

func BuildNewGoogleDrive3k(client *http.Client, subject string, ctx context.Context) *GoogleDrive3k {
	newGoogleDrive3k := &GoogleDrive3k{}
	service, err := drive.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Fatalf(err.Error())
	}
	newGoogleDrive3k.Service = service
	newGoogleDrive3k.Subject = subject
	newGoogleDrive3k.Jobs = &sync.WaitGroup{}
	return newGoogleDrive3k
}

type GoogleDrive3k struct {
	Service *drive.Service
	Subject string
	Jobs    *sync.WaitGroup
}

type DriveFile struct {
	OSFileInfo        os.FileInfo
	GoogleDriveObject *drive.File
	Blob              []byte
}

type FileTransfer struct {
	NewOwner string
	DriveAPI *GoogleDrive3k
	Files    []string
}

func (receiver *GoogleDrive3k) GetAbout() *drive.About {
	log.Printf("Getting Drive.About of [%s]\n", receiver.Subject)
	response, err := receiver.Service.About.Get().Fields("*").Do()
	if err != nil {
		log.Println(err.Error())
		return nil
	}
	return response
}

/*Files*/

func (receiver *GoogleDrive3k) GetFileById(fileId string) *drive.File {
	file, err := receiver.Service.Files.Get(fileId).Fields("*").Do()
	if err != nil {
		if strings.Contains(err.Error(), "File not found:") {
			log.Println(err.Error())
			return nil
		}
		log.Println(err.Error())
		log.Println("Error encountered Sleeping for 2 seconds...")
		time.Sleep(time.Second * 2)
		return receiver.GetFileById(fileId)
	}
	log.Printf("Returned [%s] -> \"%s\"\n", fileId, file.Name)
	return file
}

func (receiver *GoogleDrive3k) QueryFiles(q string) []*drive.File {
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

func (receiver *GoogleDrive3k) MoveFile(fileId, parentFolderId string) *drive.File {
	updatedDriveFile, err := receiver.Service.Files.Update(
		fileId,
		&drive.File{}).
		AddParents(parentFolderId).Do()
	if err != nil {
		log.Fatalf(err.Error())
	}
	log.Printf("Drive file [%s] moved to --> [%s]\n", fileId, parentFolderId)
	return updatedDriveFile
}

func (receiver *GoogleDrive3k) CopyFile(fileId, parentFolderId, fileName string) *drive.File {
	msg := "Copy of [" + fileId + "]"
	response, err := receiver.Service.Files.Copy(fileId, &drive.File{Parents: []string{parentFolderId}}).Do()
	if err != nil {
		log.Println(msg + " FAILED...")
		if strings.Contains(err.Error(), "This file cannot be copied by the user.") {
			log.Printf("%s\n\tFile Id: %s\n\tFile Name: %s\n\tFile Location: %s\n\n", err.Error(), fileId, fileName, parentFolderId)
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

func (receiver *GoogleDrive3k) ChangeFileOwner(newOwner, fileId string, doit bool) *drive.Permission {
	changeOwnerRequest := GetTransferCall(newOwner, fileId, receiver.Service)
	msg := "File [" + fileId + "] old owner [" + receiver.Subject + "] -> new owner [" + newOwner + "] "
	if doit {
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
				return receiver.ChangeFileOwner(newOwner, fileId, doit)
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

func (receiver *GoogleDrive3k) ChangeFileOwnerWorker(newOwner, fileId string, doit bool, wg *sync.WaitGroup) {
	receiver.ChangeFileOwner(newOwner, fileId, doit)
	wg.Done()
}

func (receiver *GoogleDrive3k) UploadFile(absoluteFilePath, parentFolderId string) (*drive.File, error) {
	byteCount := func(b int64) string {
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
	reader, err := os.Open(absoluteFilePath)
	if err != nil {
		log.Fatalf(err.Error())
		panic(err)
	}
	fileInfo, _ := reader.Stat()
	var metaData = &drive.File{Name: fileInfo.Name()}
	if parentFolderId != "" {
		var parents []string
		parents = append(parents, parentFolderId)
		metaData.Parents = parents
	}
	progressUpdater := googleapi.ProgressUpdater(func(now, size int64) {
		log.Println("CurrentFile:",
			absoluteFilePath,
			"["+byteCount(now), "of", byteCount(fileInfo.Size())+"]")
	})
	result, err := receiver.Service.Files.Create(metaData).Media(reader).ProgressUpdater(progressUpdater).Do()
	reader.Close()
	return result, err
}

/*Folders*/
func (receiver *GoogleDrive3k) CopyFolder(sourceFolderId, newSourceFolderName, parentFolderId string) {

	/*Get source folder*/
	sourceFolder := receiver.GetFileById(sourceFolderId)
	sourceFolder.Name = newSourceFolderName
	msg := "Copy of [" + sourceFolder.Name + "]"

	/*Create a copy source folder*/
	sourceCopy := receiver.CreateFolder(sourceFolder.Name, parentFolderId, nil, false)

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

func (receiver *GoogleDrive3k) CreateFolder(folderName, parentFolderId string, permissions []*drive.Permission, restricted bool) *drive.File {
	file := &drive.File{}
	file.MimeType = "application/vnd.google-apps.folder"
	file.Name = folderName
	file.Parents = append(file.Parents, parentFolderId)

	driveFileCreateResponse, filesCreateErr := receiver.Service.Files.Create(file).Do()
	if filesCreateErr != nil {
		if strings.Contains(filesCreateErr.Error(), "limit") {
			log.Println(filesCreateErr.Error())
			log.Println("Api limit reached. Sleeping for 2 seconds...")
			time.Sleep(time.Second * 2)
			return driveFileCreateResponse
		}
	}

	if permissions != nil {
		for _, permission := range permissions {
			permissionResponse, err := receiver.Service.Permissions.Create(driveFileCreateResponse.Id, permission).SendNotificationEmail(false).Do()
			if err != nil {
				log.Println(err.Error())
			} else {
				log.Printf("Shared \"%s\" [%s] to <%s> as a {%s}", driveFileCreateResponse.Name, driveFileCreateResponse.Id, permission.EmailAddress, permissionResponse.Role)
			}
		}
	}

	log.Printf("Created folder %s[%s]", driveFileCreateResponse.Name, driveFileCreateResponse.Id)
	return driveFileCreateResponse
}

func (receiver *GoogleDrive3k) GetNestedFiles(targetFolderId string) []*drive.File {
	targetFolder := receiver.GetFileById(targetFolderId)
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

func (receiver *GoogleDrive3k) GetNestedFilesUsingRoutines(targetFolderId string) []*drive.File {
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

/*Sharing*/
func (receiver *GoogleDrive3k) GetFilePermissions(file *drive.File) string {
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

func (receiver *GoogleDrive3k) RemoveUserPermission(fileId string, permission *drive.Permission, execute bool) error {
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

func (receiver *GoogleDrive3k) RemovePermissionByID(fileID, permissionID string, execute bool) error {
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

func (receiver *GoogleDrive3k) ShareFile(fileId, email, accountType, role string, notify bool, doit bool) *drive.Permission {

	if doit {
		response, err := receiver.Service.
			Permissions.
			Create(fileId, &drive.Permission{EmailAddress: email, Type: accountType, Role: strings.ToLower(role)}).
			Fields("*").
			SendNotificationEmail(notify).
			Do()

		if err != nil {
			log.Printf("Sharing: %s, to: %s as [%s, %s] FAILED", fileId, email, accountType, role)
			log.Fatalf(err.Error())
		} else {
			log.Printf("Sharing: %s, to: %s as [%s, %s] SUCCESS", fileId, email, accountType, role)
		}
		return response
	}

	log.Printf("Sharing: %s, to: %s as [%s, %s] DID NOT EXECUTE", fileId, email, accountType, role)
	return &drive.Permission{}

}

func (receiver *GoogleDrive3k) PermissionShareHandler(calls []*drive.PermissionsCreateCall, doit bool) {
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
				if doit == true {
					_, err := worker.Do()
					if err != nil {
						log.Println(err.Error())
						log.Printf("FAILED --> Share File[%s] to %s<%s>", url, user, role)
					}
					log.Printf("SUCCESS --> Share File[%s] to %s<%s>", url, user, role)
				} else {
					log.Printf("DID NOT EXECUTE --> Share File[%s] to %s<%s>", url, user, role)
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

/*Workers*/
func (receiver *GoogleDrive3k) CopyFileWorker(fileInformation []string, wg *sync.WaitGroup) {
	receiver.CopyFile(fileInformation[0], fileInformation[1], fileInformation[2])
	wg.Done()
}

func (receiver *GoogleDrive3k) RemoveUserPermissionWorker(fileID string, permission *drive.Permission, wg *sync.WaitGroup, execute bool) error {
	err := receiver.RemoveUserPermission(fileID, permission, execute)
	wg.Done()
	return err //Channels?
}

func (receiver *GoogleDrive3k) RemovePermissionByIDWorker(fileID, permissionId string, wg *sync.WaitGroup, execute bool) error {
	err := receiver.RemovePermissionByID(fileID, permissionId, execute)
	wg.Done()
	return err //Channels?
}

func (receiver *GoogleDrive3k) GetBlob(file *drive.File) (*drive.File, []byte) {
	log.Printf("Retrieving %s as a blob from Google Drive...\n", file.Id)
	var blob []byte
	var err error
	var response *http.Response

	if strings.Contains(file.MimeType, "shortcut") ||
		strings.Contains(file.MimeType, "folder") {
		log.Printf("File \"%s\" [%s] is a %s and will not be downloaded\n", file.Name, file.Id, file.MimeType)
		return file, nil
	} else if strings.Contains(file.MimeType, "google") {
		osMimeType, ext := GetOSMimeType(file.MimeType)
		if osMimeType == "" {
			return file, nil
		}
		file.FileExtension = ext
		file.OriginalFilename = file.Name + ext
		response, err = receiver.Service.Files.Export(file.Id, osMimeType).Download()
		log.Printf("File \"%s\" [%s] - Converted from %s to a %s\n", file.Name, file.Id, strings.Split(file.MimeType, "vnd.")[1], osMimeType)
	} else {
		log.Printf("File \"%s\" [%s] - saved as from %s\n", file.Name, file.Id, file.FullFileExtension)
		response, err = receiver.Service.Files.Get(file.Id).Download()
	}

	if err != nil {
		seconds := 10
		log.Printf("%s, backing off for %d seconds...\n", err.Error(), seconds)
		time.Sleep(time.Second * time.Duration(int64(seconds)))
		return receiver.GetBlob(file)
	}

	blob, err = ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf(err.Error())
	}

	if file.Size < 1 {
		file.Size = int64(len(blob))
	}

	log.Printf("Size: %s, File: \"%s\", ID:[%s], Type: %s\n", ByteCount(int64(len(blob))), file.Name, file.Id, file.MimeType)
	return file, blob
}

func (receiver *GoogleDrive3k) GetClientDriveFile(file *drive.File) *DriveFile {
	callbackFile, blob := receiver.GetBlob(file)
	localFile := &DriveFile{
		Blob:              blob,
		GoogleDriveObject: callbackFile,
	}
	return localFile
}

func (df *DriveFile) Save(locationPath string) *DriveFile {
	if df.Blob == nil {
		log.Printf("Cannot save %s [%s] <https://drive.google.com/drive/folders/%s> because it has no data\n", df.GoogleDriveObject.Name, df.GoogleDriveObject.Id, df.GoogleDriveObject.Parents[0])
		return df
	}
	err := os.WriteFile(locationPath+df.GoogleDriveObject.OriginalFilename, df.Blob, os.ModePerm)
	if err != nil {
		if err != nil {
			log.Println(err.Error())
			return df
		}
	}
	fileInfo, err := os.Stat(locationPath + df.GoogleDriveObject.Name)
	if err != nil {
		log.Println(err.Error())
		return df
	}
	df.OSFileInfo = fileInfo
	log.Printf("Downloaded %s to [%s]\n", df.GoogleDriveObject.Name, locationPath)

	return df
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
