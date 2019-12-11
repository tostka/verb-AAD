@{
  PSDependOptions  = @{
      Target = 'CurrentUser'
  }
  PSScriptAnalyzer = 'latest'
  platyPS          = 'latest'
  Pester = @{
    Name = 'Pester'
    DependencyType ='PSGalleryModule'
    Parameters =@{
      Repository = 'PSGallery'
      SkipPublisherCheck = $true
    } 
   }
}